"""The fetch/map/write/ack/commit loop, shared by tail and backfill.

    fetch page -> map -> dedup -> buffer -> flush (ACK) -> THEN commit cursor

Everything correctness-critical about this connector is the order of the last
three steps, and they appear exactly once in the codebase: here. Tail and
backfill differ only in how the first cursor is obtained and whether the stream
terminates, so they share this function rather than reimplementing the order.
See docs/SPEC.md §5 and §6.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from ocsf_connector.domain import Cursor, OcsfEvent
from ocsf_connector.mapping.base import Mapper
from ocsf_connector.sinks.base import Sink
from ocsf_connector.sources.base import Source
from ocsf_connector.state.store import StateStore
from ocsf_connector.telemetry.base import Metrics, NullMetrics


@dataclass(frozen=True, slots=True)
class RunStats:
    pages: int = 0
    mapped: int = 0
    written: int = 0
    duplicates_skipped: int = 0
    commits: int = 0
    exhausted: bool = False
    """True when a bounded range ran out of pages, i.e. backfill completed."""


async def run(
    *,
    source: Source,
    mapper: Mapper,
    sink: Sink,
    store: StateStore,
    stream: str,
    start: Callable[[], Awaitable[Cursor]],
    on_idle: Callable[[], Awaitable[None]] | None = None,
    max_pages: int | None = None,
    metrics: Metrics | None = None,
    clock: Callable[[], float] = time.time,
    purge_every_seconds: float = 3600.0,
) -> RunStats:
    """Drive one stream until it is exhausted or ``max_pages`` is reached.

    ``start`` is called only when the store has no cursor for this stream --
    once a cursor exists the runner resumes from it and never recomputes a start
    position from a timestamp (docs/SPEC.md §2.1).

    ``on_idle`` is awaited after an empty page. In tail mode an empty page means
    "caught up", not "finished", so the caller sleeps there and the loop
    re-requests. ``max_pages`` bounds an otherwise infinite tail; it exists for
    tests and for graceful shutdown, not as a throttle.

    ``purge_every_seconds`` paces the seen-set reclaim. The runner owns it
    because nothing else can: a tail never restarts, so a purge at startup would
    run exactly once in the mode that accumulates rows forever.
    """
    # Silence by default: the connector must not need an observability stack to
    # run (docs/SPEC.md §7).
    telemetry = metrics if metrics is not None else NullMetrics()

    cursor = await store.get_cursor(stream)
    if cursor is None:
        cursor = await start()

    # The batch is addressed by the cursor it began at. That value is stable
    # across a replay, so re-flushing overwrites rather than duplicates even if
    # the replayed batch covers a different number of pages -- any events the
    # shorter batch leaves out are picked up by the batch that starts where it
    # ended. See docs/SPEC.md §5.2.
    batch_key = cursor
    batch_opened_at = clock()
    last_purge_at = batch_opened_at
    pending: list[str] = []
    pages = mapped = written = duplicates = commits = 0
    exhausted = False

    while max_pages is None or pages < max_pages:
        try:
            page = await source.fetch(cursor)
        except BaseException:
            telemetry.count_error(stage="source", stream=stream)
            raise
        pages += 1

        # Map before dedup, deliberately. Mapping every record -- including one
        # already delivered -- keeps unmapped_event_type_total counting on
        # replay, which is the source-drift alarm. Filtering first would let a
        # new unknown eventType go quiet the moment it repeats. Mapping is a
        # total function (docs/SPEC.md §3.3), so this cannot fail on a dupe.
        events = [mapper.map(record) for record in page.records]
        mapped += len(events)

        unseen = set(await store.filter_unseen([event.uid for event in events]))
        fresh: list[OcsfEvent] = []
        for event in events:
            if event.uid in unseen:
                unseen.discard(event.uid)  # collapses duplicates within one page
                fresh.append(event)
        duplicates += len(events) - len(fresh)

        # Only events whose timestamp actually parsed. An unparseable `published`
        # maps to 0 by design (§3.3), and 0 here would mean a lag of now() --
        # more than fifty years -- permanently wrecking the p99 of the headline
        # SLI, and writing 0 as last_published when a page holds nothing else.
        # No observation beats a false one; the event itself still ships.
        dated = [event.time_ms for event in events if event.time_ms > 0]
        if dated:
            newest = max(dated)
            await store.record_published(stream, newest)
            # The one use `published` is safe for: how far behind we are, never
            # where to resume from (§2.1).
            telemetry.record_ingest_lag(clock() - newest / 1000, stream=stream)

        await sink.write(fresh)
        pending.extend(event.uid for event in fresh)
        written += len(fresh)
        telemetry.count_events(len(fresh), stream=stream)

        next_cursor = page.next_cursor
        exhausted = next_cursor is None

        if exhausted or sink.should_flush:
            try:
                await sink.flush(batch_key)
            except BaseException:
                telemetry.count_error(stage="sink", stream=stream)
                raise
            # --- the gap. A crash here replays the batch above; the flush is
            # idempotent on batch_key, so the replay overwrites it. Committing
            # before this line instead would lose the batch outright. Nothing
            # else belongs between these two lines -- telemetry included, which
            # is why the lag is recorded after the commit and not around it.
            await store.commit(stream, next_cursor, pending, mapper.mapping_version)
            commits += 1
            telemetry.record_commit_lag(clock() - batch_opened_at, stream=stream)
            pending = []
            batch_key = next_cursor if next_cursor is not None else batch_key
            batch_opened_at = clock()

            # Housekeeping: after the commit, never between it and the flush.
            # Paced off the timestamp just read rather than taking another --
            # the clock is injected, and the telemetry suite pins exact lag
            # values, so it is really asserting on tick positions. An extra
            # call here would break assertions that have nothing to do with
            # purging.
            #
            # Tied to commits because a commit is when the seen-set grows.
            # Expired uids are already ignored by filter_unseen, so this
            # reclaims rather than corrects; left undone the set grows for the
            # life of the stream, and a tail never restarts to clear it.
            # Allowed to raise: a store that cannot delete probably cannot
            # commit either, and carrying on against a broken store quietly is
            # the worse failure.
            if batch_opened_at - last_purge_at >= purge_every_seconds:
                last_purge_at = batch_opened_at
                await store.purge_expired()

        if exhausted:
            break

        assert next_cursor is not None
        cursor = next_cursor

        if not page.records and on_idle is not None:
            await on_idle()

    return RunStats(
        pages=pages,
        mapped=mapped,
        written=written,
        duplicates_skipped=duplicates,
        commits=commits,
        exhausted=exhausted,
    )
