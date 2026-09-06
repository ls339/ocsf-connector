"""The tests this connector exists to pass.

The commit order -- flush, ack, *then* cursor -- is the whole delivery
guarantee (docs/SPEC.md §5). These kill the runner in the window that order
creates and assert what survives.
"""

from __future__ import annotations

import pytest

from ocsf_connector.runner.loop import run
from ocsf_connector.state.memory import InMemoryStateStore
from tests.doubles import (
    CountingMapper,
    CrashOnCommit,
    FailingSink,
    RecordingSink,
    ScriptedSource,
    SimulatedCrash,
    chain,
)

STREAM = "okta-system-log"


async def test_crash_between_ack_and_commit_delivers_each_uid_exactly_once() -> None:
    """Kill the process after the sink acknowledges and before the cursor is
    committed, restart, and assert every event lands exactly once.

    docs/SPEC.md §5 calls this the artifact worth pointing a buyer at.
    """
    source = ScriptedSource(chain([["a1", "a2"], ["b1", "b2"], ["c1", "c2"]]))
    sink = RecordingSink()
    durable = InMemoryStateStore()

    with pytest.raises(SimulatedCrash):
        await run(
            source=source,
            mapper=CountingMapper(),
            sink=sink,
            store=CrashOnCommit(durable, crash_on=2),
            stream=STREAM,
            start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
        )

    # The sink took the second batch; the cursor never moved past the first.
    assert await durable.get_cursor(STREAM) == "c1"

    # Restart: same durable state, same sink, a fresh runner.
    stats = await run(
        source=ScriptedSource(source.pages),
        mapper=CountingMapper(),
        sink=sink,
        store=durable,
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
    )

    delivered = sink.delivered()
    assert sorted(delivered) == ["a1", "a2", "b1", "b2", "c1", "c2"]
    assert len(delivered) == len(set(delivered)), f"duplicates at the sink: {delivered}"
    assert stats.exhausted


async def test_replayed_batch_overwrites_its_object_rather_than_adding_one() -> None:
    """Exactly-once across a crash rests on the write being idempotent, not on
    the seen-set -- an atomic commit loses the seen-set in the same crash that
    causes the replay. The batch is addressed by the cursor it began at, which
    is stable across replay. See docs/SPEC.md §5.2."""
    source = ScriptedSource(chain([["a1"], ["b1"], ["c1"]]))
    sink = RecordingSink()
    durable = InMemoryStateStore()

    with pytest.raises(SimulatedCrash):
        await run(
            source=source,
            mapper=CountingMapper(),
            sink=sink,
            store=CrashOnCommit(durable, crash_on=2),
            stream=STREAM,
            start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
        )
    assert sink.flushes == ["c0", "c1"]

    await run(
        source=ScriptedSource(source.pages),
        mapper=CountingMapper(),
        sink=sink,
        store=durable,
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
    )

    # c1 was flushed twice and is one object holding one copy of b1.
    assert sink.flushes == ["c0", "c1", "c1", "c2"]
    assert [e.uid for e in sink.objects["c1"]] == ["b1"]


async def test_sink_failure_does_not_advance_the_cursor() -> None:
    """A sink that raises has not acknowledged, so nothing licenses a commit."""
    source = ScriptedSource(chain([["a1", "a2"]]))
    store = InMemoryStateStore()

    with pytest.raises(OSError):
        await run(
            source=source,
            mapper=CountingMapper(),
            sink=FailingSink(),
            store=store,
            stream=STREAM,
            start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
        )

    assert await store.get_cursor(STREAM) is None
    assert not store.has_committed(STREAM)


async def test_source_side_duplicate_uuid_reaches_the_sink_once() -> None:
    """What the seen-set is actually for: Okta documents that paginating a log
    query "may lead to skipped or duplicated events" (docs/SPEC.md §2.1)."""
    source = ScriptedSource(chain([["a1", "a2"], ["a2", "b1"]]))
    sink = RecordingSink()

    stats = await run(
        source=source,
        mapper=CountingMapper(),
        sink=sink,
        store=InMemoryStateStore(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
    )

    assert sink.delivered() == ["a1", "a2", "b1"]
    assert stats.duplicates_skipped == 1


async def test_duplicate_within_a_single_page_reaches_the_sink_once() -> None:
    source = ScriptedSource(chain([["a1", "a1", "a2"]]))
    sink = RecordingSink()

    await run(
        source=source,
        mapper=CountingMapper(),
        sink=sink,
        store=InMemoryStateStore(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
    )

    assert sink.delivered() == ["a1", "a2"]


async def test_mapping_runs_on_replayed_records_so_drift_keeps_counting() -> None:
    """Dedup runs after mapping on purpose: filtering first would let a new
    unknown eventType stop incrementing unmapped_event_type_total the moment it
    repeats (docs/SPEC.md §3.3)."""
    source = ScriptedSource(chain([["a1"], ["a1"]]))
    mapper = CountingMapper()

    await run(
        source=source,
        mapper=mapper,
        sink=RecordingSink(),
        store=InMemoryStateStore(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
    )

    assert mapper.seen_records == ["a1", "a1"]


async def test_resume_uses_the_stored_cursor_and_never_restarts_the_stream() -> None:
    """Once a cursor exists the runner must not recompute a start position --
    that is the timestamp-watermark bug the whole design avoids (§2.1)."""
    source = ScriptedSource(chain([["a1"], ["b1"], ["c1"]]))
    store = InMemoryStateStore()
    await store.commit(STREAM, "c2", [], "okta-2026.09.01")

    async def must_not_be_called() -> str:
        raise AssertionError("recomputed a start position despite a stored cursor")

    stats = await run(
        source=source,
        mapper=CountingMapper(),
        sink=RecordingSink(),
        store=store,
        stream=STREAM,
        start=must_not_be_called,
    )

    assert source.fetched == ["c2"]
    assert stats.pages == 1


async def test_empty_polling_page_is_not_end_of_stream() -> None:
    """In tail mode an empty page means "caught up", not "finished" (§2.2)."""
    source = ScriptedSource(chain([["a1"], [], ["b1"]], terminal=False))
    sink = RecordingSink()
    idle = 0

    async def on_idle() -> None:
        nonlocal idle
        idle += 1

    stats = await run(
        source=source,
        mapper=CountingMapper(),
        sink=sink,
        store=InMemoryStateStore(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
        on_idle=on_idle,
        max_pages=3,
    )

    assert idle == 1
    assert not stats.exhausted
    assert sink.delivered() == ["a1", "b1"]


async def test_backfill_terminates_when_next_cursor_is_absent() -> None:
    source = ScriptedSource(chain([["a1"], ["b1"]]))
    store = InMemoryStateStore()

    stats = await run(
        source=source,
        mapper=CountingMapper(),
        sink=RecordingSink(),
        store=store,
        stream=STREAM,
        start=lambda: source.start_backfill("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z"),
    )

    assert stats.exhausted
    assert await store.get_cursor(STREAM) is None
    assert store.has_committed(STREAM), "a finished range must not read as a fresh stream"


async def test_commit_records_the_mapping_version_that_produced_the_batch() -> None:
    source = ScriptedSource(chain([["a1"]]))
    store = InMemoryStateStore()

    await run(
        source=source,
        mapper=CountingMapper(mapping_version="okta-2026.09.04"),
        sink=RecordingSink(),
        store=store,
        stream=STREAM,
        start=lambda: source.start_backfill("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z"),
    )

    assert await store.get_mapping_version(STREAM) == "okta-2026.09.04"
