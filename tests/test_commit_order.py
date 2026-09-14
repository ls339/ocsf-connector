"""The tests this connector exists to pass.

The commit order -- flush, ack, *then* cursor -- is the whole delivery
guarantee (docs/SPEC.md §5). These kill the runner in the window that order
creates and assert what survives.

Every case runs twice, against the in-memory store and the durable one
(``conftest.StoreHarness``). That is not ceremony: in the durable run a restart
closes the SQLite connection and reopens the file, so "the same durable state, a
fresh runner" means what it says rather than being an object that happened to
outlive a raised exception.
"""

from __future__ import annotations

import pytest

from ocsf_connector.runner.loop import run
from tests.conftest import StoreHarness
from tests.doubles import (
    CountingMapper,
    CrashOnCommit,
    DriftingStartSource,
    FailingSink,
    RecordingSink,
    ScriptedSource,
    SimulatedCrash,
    chain,
)

STREAM = "okta-system-log"


async def test_crash_between_ack_and_commit_delivers_each_uid_exactly_once(
    stores: StoreHarness,
) -> None:
    """Kill the process after the sink acknowledges and before the cursor is
    committed, restart, and assert every event lands exactly once.

    docs/SPEC.md §5 calls this the artifact worth pointing a buyer at.
    """
    source = ScriptedSource(chain([["a1", "a2"], ["b1", "b2"], ["c1", "c2"]]))
    sink = RecordingSink()
    durable = stores.open()

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
    durable = stores.reopen()
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


async def test_replayed_batch_overwrites_its_object_rather_than_adding_one(
    stores: StoreHarness,
) -> None:
    """Exactly-once across a crash rests on the write being idempotent, not on
    the seen-set -- an atomic commit loses the seen-set in the same crash that
    causes the replay. The batch is addressed by the cursor it began at, which
    is stable across replay. See docs/SPEC.md §5.2."""
    source = ScriptedSource(chain([["a1"], ["b1"], ["c1"]]))
    sink = RecordingSink()
    durable = stores.open()

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
        store=stores.reopen(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
    )

    # c1 was flushed twice and is one object holding one copy of b1.
    assert sink.flushes == ["c0", "c1", "c1", "c2"]
    assert [e.uid for e in sink.objects["c1"]] == ["b1"]


async def test_sink_failure_does_not_advance_the_cursor(stores: StoreHarness) -> None:
    """A sink that raises has not acknowledged, so nothing licenses a commit."""
    source = ScriptedSource(chain([["a1", "a2"]]))
    store = stores.open()

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


async def test_source_side_duplicate_uuid_reaches_the_sink_once(stores: StoreHarness) -> None:
    """What the seen-set is actually for: Okta documents that paginating a log
    query "may lead to skipped or duplicated events" (docs/SPEC.md §2.1)."""
    source = ScriptedSource(chain([["a1", "a2"], ["a2", "b1"]]))
    sink = RecordingSink()

    stats = await run(
        source=source,
        mapper=CountingMapper(),
        sink=sink,
        store=stores.open(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
    )

    assert sink.delivered() == ["a1", "a2", "b1"]
    assert stats.duplicates_skipped == 1


async def test_duplicate_within_a_single_page_reaches_the_sink_once(
    stores: StoreHarness,
) -> None:
    source = ScriptedSource(chain([["a1", "a1", "a2"]]))
    sink = RecordingSink()

    await run(
        source=source,
        mapper=CountingMapper(),
        sink=sink,
        store=stores.open(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
    )

    assert sink.delivered() == ["a1", "a2"]


async def test_mapping_runs_on_replayed_records_so_drift_keeps_counting(
    stores: StoreHarness,
) -> None:
    """Dedup runs after mapping on purpose: filtering first would let a new
    unknown eventType stop incrementing unmapped_event_type_total the moment it
    repeats (docs/SPEC.md §3.3)."""
    source = ScriptedSource(chain([["a1"], ["a1"]]))
    mapper = CountingMapper()

    await run(
        source=source,
        mapper=mapper,
        sink=RecordingSink(),
        store=stores.open(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
    )

    assert mapper.seen_records == ["a1", "a1"]


async def test_resume_uses_the_stored_cursor_and_never_restarts_the_stream(
    stores: StoreHarness,
) -> None:
    """Once a cursor exists the runner must not recompute a start position --
    that is the timestamp-watermark bug the whole design avoids (§2.1)."""
    source = ScriptedSource(chain([["a1"], ["b1"], ["c1"]]))
    store = stores.open()
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


async def test_empty_polling_page_is_not_end_of_stream(stores: StoreHarness) -> None:
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
        store=stores.open(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
        on_idle=on_idle,
        max_pages=3,
    )

    assert idle == 1
    assert not stats.exhausted
    assert sink.delivered() == ["a1", "b1"]


async def test_backfill_terminates_when_next_cursor_is_absent(stores: StoreHarness) -> None:
    source = ScriptedSource(chain([["a1"], ["b1"]]))
    store = stores.open()

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


async def test_commit_records_the_mapping_version_that_produced_the_batch(
    stores: StoreHarness,
) -> None:
    source = ScriptedSource(chain([["a1"]]))
    store = stores.open()

    await run(
        source=source,
        mapper=CountingMapper(mapping_version="okta-2026.09.04"),
        sink=RecordingSink(),
        store=store,
        stream=STREAM,
        start=lambda: source.start_backfill("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z"),
    )

    assert await store.get_mapping_version(STREAM) == "okta-2026.09.04"


async def test_crash_before_the_first_commit_replays_into_the_same_object(
    stores: StoreHarness,
) -> None:
    """The first batch has no stored cursor behind it -- it is addressed by
    whatever the opening query resolved to (docs/SPEC.md §2.2). A stable opening
    cursor makes the replay an overwrite, exactly like every later batch."""
    source = ScriptedSource(chain([["a1"], ["b1"]]))
    sink = RecordingSink()
    durable = stores.open()

    with pytest.raises(SimulatedCrash):
        await run(
            source=source,
            mapper=CountingMapper(),
            sink=sink,
            store=CrashOnCommit(durable, crash_on=1),
            stream=STREAM,
            start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
        )

    durable = stores.reopen()
    assert await durable.get_cursor(STREAM) is None, "nothing committed yet"
    assert sink.flushes == ["c0"]

    await run(
        source=ScriptedSource(source.pages),
        mapper=CountingMapper(),
        sink=sink,
        store=durable,
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
    )

    assert sorted(sink.objects) == ["c0", "c1"]
    delivered = sink.delivered()
    assert sorted(delivered) == ["a1", "b1"]
    assert len(delivered) == len(set(delivered)), f"duplicates at the sink: {delivered}"


async def test_a_moving_opening_cursor_breaks_first_batch_idempotency(
    stores: StoreHarness,
) -> None:
    """Why docs/SPEC.md §5.2 requires tail's opening ``since`` to come from
    configuration and never from ``now()``.

    The runner cannot enforce it -- it has no way to know how ``start`` computed
    its answer -- so the obligation sits with the mode entry point, and this test
    is what keeps that obligation honest. If a change ever makes this test fail,
    the runner has taken the guarantee over and §5.2 should be updated to say so.
    """
    source = DriftingStartSource(chain([["a1"], ["b1"]]))
    sink = RecordingSink()
    durable = stores.open()

    with pytest.raises(SimulatedCrash):
        await run(
            source=source,
            mapper=CountingMapper(),
            sink=sink,
            store=CrashOnCommit(durable, crash_on=1),
            stream=STREAM,
            start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
        )

    await run(
        source=source,
        mapper=CountingMapper(),
        sink=sink,
        store=stores.reopen(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
    )

    # The same page landed in two objects, keyed s1 and s2, because the opening
    # cursor moved between the crash and the restart.
    assert sink.flushes == ["s1", "s2", "c1"]
    assert sink.delivered().count("a1") == 2
