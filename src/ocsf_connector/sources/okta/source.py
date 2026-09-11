"""Okta System Log source: open a query, fetch a page, follow ``next``.

The only URLs built here are the two opening queries. Every later cursor is the
``next`` URL from the ``Link`` header, sent as-is and handed back unread
(docs/SPEC.md §2.2). Rate limits and transient failures are absorbed here, so
the runner sees either a page or a failure worth stopping for (§2.3).

Credentials sit behind :class:`TokenProvider`; nothing in this module touches a
key (§2.4).
"""

from __future__ import annotations

import asyncio
import random
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx

from ocsf_connector.sources.base import Cursor, Page
from ocsf_connector.sources.okta.auth import TokenProvider

LOGS_PATH = "/api/v1/logs"

MAX_LIMIT = 1000
"""Okta's upper bound on ``limit``, and the v1 page size (docs/SPEC.md §2.3)."""

REQUEST_TIMEOUT_SECONDS = 35.0
"""Okta times a query out at 30 seconds (docs/SPEC.md §2.3). Waiting a little
longer lets Okta's own answer arrive instead of being cut off client-side."""

RATE_LIMIT_WINDOW_SECONDS = 60.0
"""Okta's counters reset roughly every 60 seconds (docs/SPEC.md §2.3). The wait
when a 429 carries no ``X-Rate-Limit-Reset``; twice this caps any single wait, so
a nonsense header cannot park the connector."""

BACKOFF_CAP_SECONDS = 30.0

RETRYABLE_STATUS = frozenset({500, 502, 503, 504})

_LINK_VALUE = re.compile(r"<([^>]*)>([^<]*)")
_REL = re.compile(r';\s*rel\s*=\s*(?:"([^"]*)"|([^\s;,]+))', re.IGNORECASE)


class OktaApiError(Exception):
    """A failure the source will not absorb: a non-429 client error, a redirect,
    a malformed body, or a transient failure that outlasted ``max_attempts``."""

    def __init__(self, status: int | None, error_code: str | None, summary: str) -> None:
        where = "transport" if status is None else f"HTTP {status}"
        what = f"{error_code}: {summary}" if error_code else summary
        super().__init__(f"Okta {where}: {what}")
        self.status = status
        self.error_code = error_code


@dataclass(slots=True)
class OktaSource:
    """One org's System Log. Implements :class:`~ocsf_connector.sources.base.Source`.

    ``clock``, ``sleep`` and ``jitter`` are injected so rate-limit behavior is
    testable without waiting. ``clock`` is wall time, not monotonic, because
    ``X-Rate-Limit-Reset`` is a UTC epoch second.
    """

    org_url: str
    """``https://{yourOktaDomain}``. Every cursor must be a query on its logs endpoint."""
    client: httpx.AsyncClient
    tokens: TokenProvider
    name: str = "okta"
    limit: int = MAX_LIMIT
    rate_limit_reserve: int = 5
    """Wait for the reset once ``X-Rate-Limit-Remaining`` falls to this."""
    max_attempts: int = 5
    """Attempts per fetch against 5xx and transport errors. 429s do not count."""
    max_jitter_seconds: float = 2.0
    clock: Callable[[], float] = time.time
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    jitter: Callable[[], float] = random.random
    _remaining: int | None = field(default=None, init=False)
    _reset_at: float | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        # Okta accepts limit=0 (docs/SPEC.md §2.3), but such a stream can only
        # ever return empty pages.
        if not 1 <= self.limit <= MAX_LIMIT:
            raise ValueError(f"limit must be between 1 and {MAX_LIMIT}, got {self.limit}")
        if not self.org_url.startswith("https://"):
            raise ValueError(f"org_url must be an https:// URL, got {self.org_url!r}")
        self.org_url = self.org_url.rstrip("/")

    async def start_tail(self, since: str) -> Cursor:
        # A polling query: since, no until, sortOrder=ASCENDING (docs/SPEC.md
        # §2.1). Built from arguments and config alone -- never the clock -- so
        # the same configured since opens the same cursor after a restart (§5.2).
        return self._opening(since=since, sortOrder="ASCENDING")

    async def start_backfill(self, since: str, until: str) -> Cursor:
        # A bounded query (docs/SPEC.md §2.1). ASCENDING is Okta's default; it is
        # spelled out so the opening cursor says what it asks for.
        return self._opening(since=since, until=until, sortOrder="ASCENDING")

    async def fetch(self, cursor: Cursor) -> Page:
        # The one check made on a cursor. It reads no parameter and derives no
        # position; it keeps the bearer token on this org's logs endpoint even if
        # the state store hands back something else (docs/SPEC.md §2.2).
        if not cursor.startswith(f"{self.org_url}{LOGS_PATH}?"):
            raise ValueError("cursor is not a query on this org's System Log endpoint")

        failures = 0
        while True:
            await self._respect_budget()
            try:
                # httpx does not follow redirects by default, so a 3xx surfaces
                # as an error below rather than carrying the token elsewhere.
                response = await self.client.get(
                    cursor,
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {await self.tokens.token()}",
                    },
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )
            except httpx.TransportError as exc:
                failures += 1
                if failures >= self.max_attempts:
                    raise OktaApiError(
                        None, None, f"gave up after {failures} attempts: {exc!r}"
                    ) from exc
                await self.sleep(self._backoff(failures))
                continue

            self._observe_budget(response)
            status = response.status_code

            if status == 429:
                # Sleep to the reset plus jitter: every client in the org sees
                # the same reset instant, and waking them together re-trips the
                # limit (docs/SPEC.md §2.3). Not counted against max_attempts --
                # a shared budget running dry is a wait, not a failure.
                self._remaining = None
                await self.sleep(self._until(_int_header(response, "X-Rate-Limit-Reset")))
                continue
            if status in RETRYABLE_STATUS:
                failures += 1
                if failures >= self.max_attempts:
                    raise _api_error(response)
                await self.sleep(self._backoff(failures))
                continue
            if status != 200:
                raise _api_error(response)
            return _page(response)

    def _opening(self, **params: str) -> Cursor:
        if not params["since"]:
            raise ValueError("an opening query needs a since")
        return f"{self.org_url}{LOGS_PATH}?{urlencode({**params, 'limit': self.limit})}"

    def _observe_budget(self, response: httpx.Response) -> None:
        remaining = _int_header(response, "X-Rate-Limit-Remaining")
        reset = _int_header(response, "X-Rate-Limit-Reset")
        if remaining is not None and reset is not None:
            self._remaining, self._reset_at = remaining, float(reset)

    async def _respect_budget(self) -> None:
        # Wait before the 429, not after it: the connector shares the org's budget
        # with whatever else the customer runs (docs/SPEC.md §2.3).
        if self._remaining is None or self._remaining > self.rate_limit_reserve:
            return
        self._remaining = None
        await self.sleep(self._until(self._reset_at))

    def _until(self, reset_at: float | None) -> float:
        """Seconds until a rate-limit reset, bounded, plus jitter."""
        wait = RATE_LIMIT_WINDOW_SECONDS if reset_at is None else reset_at - self.clock()
        bounded = min(max(wait, 0.0), 2 * RATE_LIMIT_WINDOW_SECONDS)
        return bounded + self.jitter() * self.max_jitter_seconds

    def _backoff(self, failures: int) -> float:
        """Full jitter: uniform over ``[0, min(cap, 2**failures))`` seconds."""
        return self.jitter() * min(BACKOFF_CAP_SECONDS, 2.0**failures)


def _page(response: httpx.Response) -> Page:
    try:
        body: Any = response.json()
    except ValueError as exc:
        raise OktaApiError(response.status_code, None, "response body is not JSON") from exc
    if not isinstance(body, list) or not all(isinstance(event, dict) for event in body):
        raise OktaApiError(response.status_code, None, "expected a JSON array of events")
    return Page(records=body, next_cursor=_next_link(response))


def _next_link(response: httpx.Response) -> Cursor | None:
    """The ``rel="next"`` URL, exactly as it appears between the angle brackets.

    A bounded query's last page has none, and that absence is the only end of a
    range (docs/SPEC.md §2.2). httpx's own ``Response.links`` is not used: it
    splits a URL that contains ``;``, which is not verbatim enough for a cursor.
    """
    for header in response.headers.get_list("link"):
        for url, params in _LINK_VALUE.findall(header):
            for quoted, bare in _REL.findall(params):
                if "next" in (quoted or bare).lower().split():
                    return str(url)
    return None


def _api_error(response: httpx.Response) -> OktaApiError:
    code: str | None = None
    summary = response.reason_phrase
    try:
        body: Any = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        code = str(body["errorCode"]) if "errorCode" in body else None
        summary = str(body.get("errorSummary", summary))
    return OktaApiError(response.status_code, code, summary)


def _int_header(response: httpx.Response, name: str) -> int | None:
    value = response.headers.get(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
