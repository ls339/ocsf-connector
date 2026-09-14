"""One-shot probe against a live Okta org (docs/SPEC.md §2.2 and §2.4).

CI never runs this: CI has no credentials and makes no live calls. It exists to
answer two questions no vendor page states, and that no fixture can settle:

1. **Does a `next` link come back on the host the request was sent to?**
   ``OktaSource.fetch`` refuses a cursor that is not under the configured org's
   logs endpoint, so if Okta answers on a different host -- most plausibly with a
   custom domain -- a stream dies on its second page.
2. **Does this org's service app require DPoP?** Okta documents the setting but
   never its default; the connector supports both and has only ever been run
   against synthetic responses.

It prints no event contents, no token, and no key material: counts, hosts, and a
cursor with its opaque ``after`` masked, so the output is safe to paste into an
issue or a commit message.

Usage::

    export OKTA_ORG_URL=https://your-org.okta.com
    export OKTA_CLIENT_ID=0oa...
    export OKTA_PRIVATE_KEY_FILE=/path/to/client_key.pem   # never in the repo
    export OKTA_KID=the-kid-registered-on-the-app
    export OKTA_DPOP_KEY_FILE=/path/to/dpop_key.pem        # only if DPoP is on
    uv run python scripts/live_probe.py

These variable names belong to the probe. The connector's own configuration is
still to be designed (issue pet.6), and need not match.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from ocsf_connector.sources.okta.auth import (
    AuthError,
    BearerAuth,
    DpopAuth,
    OktaClientCredentials,
)
from ocsf_connector.sources.okta.source import LOGS_PATH, OktaApiError, OktaSource

REQUIRED = ("OKTA_ORG_URL", "OKTA_CLIENT_ID", "OKTA_PRIVATE_KEY_FILE", "OKTA_KID")


def redact(url: str) -> str:
    """The cursor with its opaque ``after`` masked.

    The host stays: the host is the thing under test. Redact the domain yourself
    before pasting if your org name is sensitive.
    """
    split = urlsplit(url)
    query = [
        (key, "REDACTED" if key == "after" else value)
        for key, value in parse_qsl(split.query, keep_blank_values=True)
    ]
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query), ""))


def default_since() -> str:
    """One hour ago.

    A probe may compute this from the clock; tail may not (§5.2). Nothing here
    persists a cursor, so the rule that makes a moving opening cursor dangerous
    does not apply.
    """
    return (datetime.now(UTC) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


async def probe() -> int:
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        print(f"set these first: {', '.join(missing)}\n\n{__doc__}")
        return 2

    org_url = os.environ["OKTA_ORG_URL"].rstrip("/")
    since = os.environ.get("OKTA_SINCE", default_since())
    dpop_file = os.environ.get("OKTA_DPOP_KEY_FILE")

    async with httpx.AsyncClient() as client:
        credentials = OktaClientCredentials(
            org_url=org_url,
            client_id=os.environ["OKTA_CLIENT_ID"],
            private_key=Path(os.environ["OKTA_PRIVATE_KEY_FILE"]).read_text(),
            kid=os.environ["OKTA_KID"],
            client=client,
        )
        auth = (
            DpopAuth(credentials, dpop_key=Path(dpop_file).read_text())
            if dpop_file
            else BearerAuth(credentials)
        )
        source = OktaSource(
            org_url=org_url,
            client=client,
            auth=auth,
            limit=int(os.environ.get("OKTA_LIMIT", "5")),
        )

        print(f"org        {urlsplit(org_url).netloc}")
        print(f"auth mode  {type(auth).__name__}")
        print(f"since      {since}")

        opening = await source.start_tail(since)
        print(f"\nopening    {redact(opening)}")

        try:
            first = await source.fetch(opening)
        except AuthError as exc:
            print(f"\nFAIL  authentication: {exc}")
            if not dpop_file:
                print("      If this says the app requires DPoP, that answers")
                print("      question 2: set OKTA_DPOP_KEY_FILE and run again.")
            return 1
        except OktaApiError as exc:
            print(f"\nFAIL  request: {exc}")
            return 1

        has_next = first.next_cursor is not None
        print(f"page 1     {len(first.records)} records, next link: {has_next}")
        if first.next_cursor is None:
            print("\nINCONCLUSIVE  a polling query should always carry a next link (§2.1).")
            print("              Widen OKTA_SINCE, or check sortOrder handling.")
            return 1

        # Question 1.
        requested_host = urlsplit(org_url).netloc
        answered_host = urlsplit(first.next_cursor).netloc
        same_host = requested_host == answered_host
        accepted = first.next_cursor.startswith(f"{org_url}{LOGS_PATH}?")
        print(f"\nnext       {redact(first.next_cursor)}")
        print(f"host       requested {requested_host} | answered {answered_host}")
        print(f"           same host: {same_host} | passes the origin check: {accepted}")

        try:
            second = await source.fetch(first.next_cursor)
        except ValueError as exc:
            print(f"\nFAIL  the connector refused its own next cursor: {exc}")
            print("      SPEC §2.2's host assumption is wrong for this org.")
            return 1
        except OktaApiError as exc:
            print(f"\nFAIL  following the next link: {exc}")
            return 1

        still_paging = second.next_cursor is not None
        print(f"page 2     {len(second.records)} records, next link: {still_paging}")
        print("\nPASS  next links stay on the requested host, and paging works.")
        print(f"      Answer to Q2: this app uses {type(auth).__name__.replace('Auth', '')}.")
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(probe()))
