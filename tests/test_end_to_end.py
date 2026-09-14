"""The whole chain: Okta source -> mapper -> sink, driven by the runner.

Every other suite tests one seam against doubles. Seams can each be right while
the composition is wrong -- a timestamp the mapper parses into something the sink
cannot partition on, a `uuid` the runner deduplicates on that the mapper never
carried through, a cursor that survives the source but not the store. So this
one wires the real OktaSource and the real OCSF mapper to the real runner, and
only the sink stays a double, because the sink is the piece that isn't built yet.

Okta is a respx mock that answers *the cursor it is given*, the way the vendor
does, so a cursor that fails to round-trip fails these tests rather than quietly
returning page one forever. Synthetic throughout (CLAUDE.md invariant 5).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
import respx

from ocsf_connector.mapping.okta import OktaOcsfMapper
from ocsf_connector.runner.loop import run
from ocsf_connector.sources.okta.source import OktaSource
from ocsf_connector.state.memory import InMemoryStateStore
from tests.doubles import FailingSink, RecordingSink

ORG = "https://synthetic.okta.example"
LOGS = f"{ORG}/api/v1/logs"
STREAM = "okta-system-log"
TOKEN = "synthetic-access-token"

SINCE = "2026-09-05T00:00:00Z"
UNTIL = "2026-09-06T00:00:00Z"
ENCODED_SINCE = "2026-09-05T00%3A00%3A00Z"
ENCODED_UNTIL = "2026-09-06T00%3A00%3A00Z"

TAIL_OPENING = f"{LOGS}?since={ENCODED_SINCE}&sortOrder=ASCENDING&limit=1000"
BACKFILL_OPENING = (
    f"{LOGS}?since={ENCODED_SINCE}&until={ENCODED_UNTIL}&sortOrder=ASCENDING&limit=1000"
)


class StaticAuth:
    """The auth seam, already covered by its own suite."""

    async def headers(self, method: str, url: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {TOKEN}"}


class FakeSleep:
    def __init__(self) -> None:
        self.slept: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.slept.append(seconds)


def record(uid: str, *, second: int = 0, event_type: str = "user.session.start") -> dict[str, Any]:
    """One Okta event, shaped like the vendor's (published is an ISO string)."""
    return {
        "uuid": uid,
        "published": f"2026-09-05T00:00:{second:02d}.000Z",
        "eventType": event_type,
        "severity": "INFO",
        "displayMessage": "User login to Okta",
        "actor": {
            "id": "00usynthetic00000001",
            "type": "User",
            "displayName": "Alex Example",
            "alternateId": "alex.example@example.com",
        },
        "client": {"ipAddress": "192.0.2.10"},
        "outcome": {"result": "SUCCESS"},
        "transaction": {"id": f"synthetic-transaction-{uid}", "type": "WEB"},
    }


def next_url(name: str) -> str:
    """A next link in Okta's documented shape: since and after together."""
    return f"{LOGS}?q=&sortOrder=ASCENDING&limit=1000&after={name}&since={ENCODED_SINCE}"


Page = tuple[list[dict[str, Any]], str | None]


def okta(pages: dict[str, Page]) -> Callable[[httpx.Request], httpx.Response]:
    """A vendor that answers the URL it was sent, and 404s anything it never
    handed out -- which is what makes a mangled cursor visible."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url not in pages:
            return httpx.Response(
                404,
                json={"errorCode": "E0000007", "errorSummary": f"not a cursor I issued: {url}"},
            )
        records, following = pages[url]
        links = [f'<{url}>; rel="self"']
        if following is not None:
            links.append(f'<{following}>; rel="next"')
        return httpx.Response(200, json=records, headers={"Link": ", ".join(links)})

    return handler


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as http:
        yield http


def make_source(client: httpx.AsyncClient, **overrides: Any) -> OktaSource:
    return OktaSource(
        org_url=ORG,
        client=client,
        auth=StaticAuth(),
        jitter=lambda: 0.5,
        **overrides,
    )


async def test_backfill_runs_to_the_page_without_a_next_link(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    """docs/SPEC.md §2.2: a missing next link is the only end of a range, and the
    runner has to see that through the real source."""
    respx_mock.get(url__startswith=LOGS).mock(
        side_effect=okta(
            {
                BACKFILL_OPENING: (
                    [record("a1", second=1), record("a2", second=2)],
                    next_url("p2"),
                ),
                next_url("p2"): ([record("b1", second=3)], None),
            }
        )
    )
    source = make_source(client)
    sink = RecordingSink()
    store = InMemoryStateStore()

    stats = await run(
        source=source,
        mapper=OktaOcsfMapper(),
        sink=sink,
        store=store,
        stream=STREAM,
        start=lambda: source.start_backfill(SINCE, UNTIL),
    )

    assert stats.exhausted, "a bounded range ends when next is absent"
    assert stats.pages == 2
    assert sorted(sink.delivered()) == ["a1", "a2", "b1"]
    assert await store.get_cursor(STREAM) is None, "a completed range commits a None cursor"
    assert store.has_committed(STREAM), "and that is distinguishable from never started"


async def test_tail_follows_an_empty_page_to_the_next_cursor(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    """An empty polling page means caught up, not finished (§2.2). The runner
    sleeps via on_idle and keeps the stream open."""
    respx_mock.get(url__startswith=LOGS).mock(
        side_effect=okta(
            {
                TAIL_OPENING: ([record("a1", second=1)], next_url("p2")),
                next_url("p2"): ([], next_url("p3")),
                next_url("p3"): ([record("c1", second=5)], next_url("p4")),
            }
        )
    )
    source = make_source(client)
    sink = RecordingSink()
    store = InMemoryStateStore()
    idle = 0

    async def on_idle() -> None:
        nonlocal idle
        idle += 1

    stats = await run(
        source=source,
        mapper=OktaOcsfMapper(),
        sink=sink,
        store=store,
        stream=STREAM,
        start=lambda: source.start_tail(SINCE),
        on_idle=on_idle,
        max_pages=3,
    )

    assert not stats.exhausted, "a polling query never ends"
    assert idle == 1, "exactly the empty page was idle"
    assert sorted(sink.delivered()) == ["a1", "c1"]
    assert await store.get_cursor(STREAM) == next_url("p4"), "resumes after the last acked page"


async def test_a_429_mid_stream_is_invisible_to_the_runner(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    """The source absorbs rate limiting (§2.3), so the runner's view is the same
    delivery it would have had -- just later."""
    sleep = FakeSleep()
    limited = httpx.Response(
        429,
        json={"errorCode": "E0000047", "errorSummary": "API call exceeded rate limit"},
        headers={"X-Rate-Limit-Remaining": "0", "X-Rate-Limit-Reset": "1788566460"},
    )
    serve = okta(
        {
            TAIL_OPENING: ([record("a1", second=1)], next_url("p2")),
            next_url("p2"): ([record("b1", second=2)], None),
        }
    )
    answers = [limited, None, None]

    def handler(request: httpx.Request) -> httpx.Response:
        reply = answers.pop(0) if answers else None
        return reply if reply is not None else serve(request)

    respx_mock.get(url__startswith=LOGS).mock(side_effect=handler)
    source = make_source(client, clock=lambda: 1788566400.0, sleep=sleep)
    sink = RecordingSink()
    store = InMemoryStateStore()

    stats = await run(
        source=source,
        mapper=OktaOcsfMapper(),
        sink=sink,
        store=store,
        stream=STREAM,
        start=lambda: source.start_tail(SINCE),
    )

    assert sorted(sink.delivered()) == ["a1", "b1"]
    assert stats.pages == 2, "the retry is the source's business, not a page"
    assert sleep.slept == [pytest.approx(61.0)], "slept to the reset, plus jitter"


async def test_a_uuid_repeated_across_pages_reaches_the_sink_once(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    """Okta documents that paginating may duplicate events (§2.1). Dedup keys on
    the mapped uid, so this only works if the mapper carried uuid through."""
    respx_mock.get(url__startswith=LOGS).mock(
        side_effect=okta(
            {
                BACKFILL_OPENING: ([record("a1", second=1)], next_url("p2")),
                next_url("p2"): ([record("a1", second=1), record("b1", second=2)], None),
            }
        )
    )
    source = make_source(client)
    sink = RecordingSink()

    stats = await run(
        source=source,
        mapper=OktaOcsfMapper(),
        sink=sink,
        store=InMemoryStateStore(),
        stream=STREAM,
        start=lambda: source.start_backfill(SINCE, UNTIL),
    )

    assert sorted(sink.delivered()) == ["a1", "b1"]
    assert stats.mapped == 3, "mapping runs before dedup, so the duplicate was mapped"
    assert stats.duplicates_skipped == 1
    assert stats.written == 2


async def test_a_sink_failure_leaves_the_cursor_where_it_was(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    """The core invariant, through the real source: no ack, no commit (§5)."""
    respx_mock.get(url__startswith=LOGS).mock(
        side_effect=okta({TAIL_OPENING: ([record("a1", second=1)], next_url("p2"))})
    )
    source = make_source(client)
    store = InMemoryStateStore()

    with pytest.raises(OSError):
        await run(
            source=source,
            mapper=OktaOcsfMapper(),
            sink=FailingSink(),
            store=store,
            stream=STREAM,
            start=lambda: source.start_tail(SINCE),
        )

    assert await store.get_cursor(STREAM) is None
    assert not store.has_committed(STREAM)


async def test_what_lands_in_the_sink_is_ocsf(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    """Spot-check the payload the sink will have to write: the identity fields a
    Security Lake object partitions and sorts on have to survive the whole trip."""
    respx_mock.get(url__startswith=LOGS).mock(
        side_effect=okta({BACKFILL_OPENING: ([record("a1", second=7)], None)})
    )
    source = make_source(client)
    sink = RecordingSink()

    await run(
        source=source,
        mapper=OktaOcsfMapper(),
        sink=sink,
        store=InMemoryStateStore(),
        stream=STREAM,
        start=lambda: source.start_backfill(SINCE, UNTIL),
    )

    (event,) = next(iter(sink.objects.values()))
    assert event.class_uid == 3002
    assert event.uid == "a1"
    assert event.time_ms == 1788566407000, "the ISO string became epoch millis"
    assert event.body["type_uid"] == 300201
    assert event.body["user"]["email_addr"] == "alex.example@example.com"
    assert event.body["src_endpoint"]["ip"] == "192.0.2.10"
    assert event.body["metadata"]["version"] == "1.3.0"
    assert event.body["unmapped"]["transaction"]["id"] == "synthetic-transaction-a1"
