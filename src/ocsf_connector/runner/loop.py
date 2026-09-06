"""The fetch/map/write/ack/commit loop, shared by tail and backfill.

    fetch page -> map -> dedup -> buffer -> flush (ACK) -> THEN commit cursor

Everything correctness-critical about this connector is the order of the last
three steps, and they appear exactly once in the codebase: here. Tail and
backfill differ only in how the first cursor is obtained and whether the stream
terminates, so they share this function rather than reimplementing the order.
See docs/SPEC.md §5 and §6.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from ocsf_connector.mapping.base import Mapper, OcsfEvent
from ocsf_connector.sinks.base import Sink
from ocsf_connector.sources.base import Cursor, Source
from ocsf_connector.state.store import StateStore


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
) -> RunStats:
    """Drive one stream until it is exhausted or ``max_pages`` is reached.

    ``start`` is called only when the store has no cursor for this stream --
    once a cursor exists the runner resumes from it and never recomputes a start
    position from a timestamp (docs/SPEC.md §2.1).

    ``on_idle`` is awaited after an empty page. In tail mode an empty page means
    "caught up", not "finished", so the caller sleeps there and the loop
    re-requests. ``max_pages`` bounds an otherwise infinite tail; it exists for
    tests and for graceful shutdown, not as a throttle.
    """
    cursor = await store.get_cursor(stream)
    if cursor is None:
        cursor = await start()

    # The batch is addressed by the cursor it began at. That value is stable
    # across a replay, so re-flushing overwrites rather than duplicates even if
    # the replayed batch covers a different number of pages -- any events the
    # shorter batch leaves out are picked up by the batch that starts where it
    # ended. See docs/SPEC.md §5.2.
    batch_key = cursor
    pending: list[str] = []
    pages = mapped = written = duplicates = commits = 0
    exhausted = False

    while max_pages is None or pages < max_pages:
        page = await source.fetch(cursor)
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

        if events:
            await store.record_published(stream, max(event.time_ms for event in events))

        await sink.write(fresh)
        pending.extend(event.uid for event in fresh)
        written += len(fresh)

        next_cursor = page.next_cursor
        exhausted = next_cursor is None

        if exhausted or sink.should_flush:
            await sink.flush(batch_key)
            # --- the gap. A crash here replays the batch above; the flush is
            # idempotent on batch_key, so the replay overwrites it. Committing
            # before this line instead would lose the batch outright.
            await store.commit(stream, next_cursor, pending, mapper.mapping_version)
            commits += 1
            pending = []
            batch_key = next_cursor if next_cursor is not None else batch_key

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
