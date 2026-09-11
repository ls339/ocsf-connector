"""The Okta source's fetch path, against synthetic responses.

Everything here is synthetic (CLAUDE.md invariant 5): the org sits under the
reserved ``.example`` TLD, addresses are RFC 5737 documentation ranges, and every
``after`` value is invented. Link headers copy the documented shape, ``since`` and
``after`` together (docs/SPEC.md §2.2).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from ocsf_connector.sources.okta.source import OktaApiError, OktaSource

ORG = "https://synthetic.okta.example"
LOGS = f"{ORG}/api/v1/logs"
SINCE = "2026-09-05T00:00:00Z"
UNTIL = "2026-09-06T00:00:00Z"
TOKEN = "synthetic-access-token"
FIXTURES = Path(__file__).parent / "fixtures" / "okta"

NEXT_1 = (
    f"{LOGS}?q=&sortOrder=ASCENDING&limit=1000"
    "&after=synthetic-after-0001&since=2026-09-05T00%3A00%3A00Z"
)
NEXT_2 = (
    f"{LOGS}?q=&sortOrder=ASCENDING&limit=1000"
    "&after=synthetic-after-0002&since=2026-09-05T00%3A00%3A00Z"
)


class StaticTokens:
    def __init__(self) -> None:
        self.calls = 0

    async def token(self) -> str:
        self.calls += 1
        return TOKEN


class FakeTime:
    """Wall clock and sleep on one timeline: sleeping advances the clock, and
    every wait is recorded instead of taken."""

    def __init__(self, now: float = 1_788_000_000.0) -> None:
        self.now = now
        self.slept: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def events() -> list[dict[str, Any]]:
    loaded: list[dict[str, Any]] = json.loads((FIXTURES / "system_log_page.json").read_text())
    return loaded


def link(url: str, rel: str) -> str:
    return f'<{url}>; rel="{rel}"'


def page(
    body: Any = None,
    *,
    next_url: str | None = NEXT_2,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """A 200. The self link always exists; next only when there is one (§2.2)."""
    links = [link(f"{LOGS}?since=2026-09-05T00%3A00%3A00Z", "self")]
    if next_url is not None:
        links.append(link(next_url, "next"))
    return httpx.Response(
        200,
        json=events() if body is None else body,
        headers={"Link": ", ".join(links), **(headers or {})},
    )


def make_source(
    client: httpx.AsyncClient,
    fake_time: FakeTime,
    tokens: StaticTokens | None = None,
    **overrides: Any,
) -> OktaSource:
    return OktaSource(
        org_url=ORG,
        client=client,
        tokens=tokens or StaticTokens(),
        clock=fake_time.clock,
        sleep=fake_time.sleep,
        jitter=lambda: 0.5,
        **overrides,
    )


@pytest.fixture
def fake_time() -> FakeTime:
    return FakeTime()


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as http:
        yield http


# --- opening a stream -------------------------------------------------------


async def test_opening_cursors_are_built_from_config_alone(client: httpx.AsyncClient) -> None:
    """docs/SPEC.md §5.2: the opening cursor is the first batch's key, so it has
    to come out the same after a restart. A clock read would break that."""

    def no_clock() -> float:
        raise AssertionError("an opening cursor must not read the clock")

    source = OktaSource(org_url=f"{ORG}/", client=client, tokens=StaticTokens(), clock=no_clock)

    tail = await source.start_tail(SINCE)
    assert tail == f"{LOGS}?since=2026-09-05T00%3A00%3A00Z&sortOrder=ASCENDING&limit=1000"
    assert await source.start_tail(SINCE) == tail, "same config, same opening cursor"

    assert await source.start_backfill(SINCE, UNTIL) == (
        f"{LOGS}?since=2026-09-05T00%3A00%3A00Z&until=2026-09-06T00%3A00%3A00Z"
        "&sortOrder=ASCENDING&limit=1000"
    )


@pytest.mark.parametrize("limit", [0, 1001])
async def test_a_limit_outside_oktas_bounds_is_refused(
    client: httpx.AsyncClient, limit: int
) -> None:
    with pytest.raises(ValueError, match="limit"):
        OktaSource(org_url=ORG, client=client, tokens=StaticTokens(), limit=limit)


async def test_a_plain_http_org_url_is_refused(client: httpx.AsyncClient) -> None:
    with pytest.raises(ValueError, match="https"):
        OktaSource(org_url="http://synthetic.okta.example", client=client, tokens=StaticTokens())


# --- fetching a page --------------------------------------------------------


async def test_fetch_sends_the_cursor_as_is_and_lifts_next_verbatim(
    client: httpx.AsyncClient, fake_time: FakeTime, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(url__startswith=LOGS).mock(return_value=page())

    result = await make_source(client, fake_time).fetch(NEXT_1)

    request = route.calls.last.request
    assert str(request.url) == NEXT_1, "the cursor reaches the wire byte-for-byte"
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert result.records == events()
    assert result.next_cursor == NEXT_2


async def test_next_is_lifted_whole_even_when_it_contains_link_separators(
    client: httpx.AsyncClient, fake_time: FakeTime, respx_mock: respx.MockRouter
) -> None:
    """A generic Link parser splits this URL at the ``;``. The cursor must not
    care what characters Okta puts in it, and rel order must not matter."""
    awkward = f"{LOGS}?after=synthetic;0003,x&since=2026-09-05T00%3A00%3A00Z"
    respx_mock.get(url__startswith=LOGS).mock(
        return_value=httpx.Response(
            200,
            json=[],
            headers=[("Link", link(awkward, "next")), ("Link", link(f"{LOGS}?since=x", "self"))],
        )
    )

    result = await make_source(client, fake_time).fetch(NEXT_1)

    assert result.next_cursor == awkward


async def test_the_last_bounded_page_has_no_next_cursor(
    client: httpx.AsyncClient, fake_time: FakeTime, respx_mock: respx.MockRouter
) -> None:
    """docs/SPEC.md §2.2: a missing next link is the only end of a range."""
    respx_mock.get(url__startswith=LOGS).mock(return_value=page(next_url=None))

    result = await make_source(client, fake_time).fetch(NEXT_1)

    assert result.records == events()
    assert result.next_cursor is None


async def test_an_empty_polling_page_still_carries_next(
    client: httpx.AsyncClient, fake_time: FakeTime, respx_mock: respx.MockRouter
) -> None:
    """docs/SPEC.md §2.2: empty means caught up, not finished."""
    respx_mock.get(url__startswith=LOGS).mock(return_value=page(body=[]))

    result = await make_source(client, fake_time).fetch(NEXT_1)

    assert result.records == []
    assert result.next_cursor == NEXT_2


@pytest.mark.parametrize(
    "cursor",
    [
        "https://elsewhere.example/api/v1/logs?since=x",
        f"{ORG}.elsewhere.example/api/v1/logs?since=x",
        f"{ORG}/api/v1/users?since=x",
        "http://synthetic.okta.example/api/v1/logs?since=x",
    ],
)
async def test_a_cursor_off_this_orgs_logs_endpoint_is_refused_before_any_request(
    client: httpx.AsyncClient, fake_time: FakeTime, respx_mock: respx.MockRouter, cursor: str
) -> None:
    """No route is mocked, so any request at all would fail this test."""
    tokens = StaticTokens()

    with pytest.raises(ValueError, match="cursor"):
        await make_source(client, fake_time, tokens).fetch(cursor)

    assert tokens.calls == 0, "the token was never even minted for it"


# --- rate limits ------------------------------------------------------------


async def test_a_429_waits_for_the_reset_plus_jitter_and_spends_no_retries(
    client: httpx.AsyncClient, fake_time: FakeTime, respx_mock: respx.MockRouter
) -> None:
    """docs/SPEC.md §2.3. Three 429s against max_attempts=2 still succeed: a
    shared budget running dry is a wait, not a failure."""
    reset = int(fake_time.now) + 20
    limited = httpx.Response(
        429,
        json={
            "errorCode": "E0000047",
            "errorSummary": "API call exceeded rate limit due to too many requests.",
        },
        headers={"X-Rate-Limit-Remaining": "0", "X-Rate-Limit-Reset": str(reset)},
    )
    route = respx_mock.get(url__startswith=LOGS).mock(side_effect=[limited] * 3 + [page()])

    result = await make_source(client, fake_time, max_attempts=2).fetch(NEXT_1)

    assert result.records == events()
    assert route.call_count == 4
    # 20s to the reset plus 1s of jitter; the later 429s find the reset already
    # past, so they wait only the jitter.
    assert fake_time.slept == [pytest.approx(21.0), pytest.approx(1.0), pytest.approx(1.0)]


async def test_a_429_without_a_reset_header_waits_a_full_window(
    client: httpx.AsyncClient, fake_time: FakeTime, respx_mock: respx.MockRouter
) -> None:
    respx_mock.get(url__startswith=LOGS).mock(side_effect=[httpx.Response(429), page()])

    await make_source(client, fake_time).fetch(NEXT_1)

    assert fake_time.slept == [pytest.approx(61.0)]


@pytest.mark.parametrize(("remaining", "waits"), [("6", False), ("5", True)])
async def test_a_low_budget_waits_for_the_reset_before_the_next_request(
    client: httpx.AsyncClient,
    fake_time: FakeTime,
    respx_mock: respx.MockRouter,
    remaining: str,
    waits: bool,
) -> None:
    """docs/SPEC.md §2.3: slow down before the 429, not after it."""
    reset = int(fake_time.now) + 30
    low = page(headers={"X-Rate-Limit-Remaining": remaining, "X-Rate-Limit-Reset": str(reset)})
    respx_mock.get(url__startswith=LOGS).mock(side_effect=[low, page()])
    source = make_source(client, fake_time, rate_limit_reserve=5)

    await source.fetch(NEXT_1)
    assert fake_time.slept == [], "the page that reported the budget is returned at once"

    await source.fetch(NEXT_2)
    assert fake_time.slept == ([pytest.approx(31.0)] if waits else [])


# --- failures ---------------------------------------------------------------


async def test_transient_failures_are_retried_with_backoff(
    client: httpx.AsyncClient, fake_time: FakeTime, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(url__startswith=LOGS).mock(
        side_effect=[httpx.Response(503), httpx.ConnectError("synthetic outage"), page()]
    )

    result = await make_source(client, fake_time).fetch(NEXT_1)

    assert result.records == events()
    assert route.call_count == 3
    assert fake_time.slept == [pytest.approx(1.0), pytest.approx(2.0)]


async def test_transient_failures_give_up_after_max_attempts(
    client: httpx.AsyncClient, fake_time: FakeTime, respx_mock: respx.MockRouter
) -> None:
    route = respx_mock.get(url__startswith=LOGS).mock(return_value=httpx.Response(502))

    with pytest.raises(OktaApiError) as caught:
        await make_source(client, fake_time, max_attempts=3).fetch(NEXT_1)

    assert caught.value.status == 502
    assert route.call_count == 3
    assert len(fake_time.slept) == 2


@pytest.mark.parametrize("status", [302, 400, 401, 403, 404])
async def test_client_errors_and_redirects_are_not_retried(
    client: httpx.AsyncClient, fake_time: FakeTime, respx_mock: respx.MockRouter, status: int
) -> None:
    """A redirect is not followed, so the bearer token cannot be carried off
    this org's endpoint by one."""
    route = respx_mock.get(url__startswith=LOGS).mock(
        return_value=httpx.Response(
            status,
            json={"errorCode": "E0000001", "errorSummary": "Api validation failed: since"},
            headers={"Location": "https://elsewhere.example/api/v1/logs"},
        )
    )

    with pytest.raises(OktaApiError) as caught:
        await make_source(client, fake_time).fetch(NEXT_1)

    assert caught.value.status == status
    assert caught.value.error_code == "E0000001"
    assert route.call_count == 1
    assert fake_time.slept == []


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, json={"not": "a list"}),
        httpx.Response(200, json=["not an event"]),
        httpx.Response(200, text="<html>synthetic proxy page</html>"),
    ],
    ids=["object", "array-of-strings", "not-json"],
)
async def test_a_malformed_page_raises(
    client: httpx.AsyncClient,
    fake_time: FakeTime,
    respx_mock: respx.MockRouter,
    response: httpx.Response,
) -> None:
    respx_mock.get(url__startswith=LOGS).mock(return_value=response)

    with pytest.raises(OktaApiError):
        await make_source(client, fake_time).fetch(NEXT_1)
