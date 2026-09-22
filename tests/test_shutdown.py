"""Stopping a run on purpose: the signal seam, and what the loop does with it.

A tail never returns on its own, so being stopped is its only ending -- which
makes these tests about the normal path, not an error path. They send real
signals to the test process, because the bug they exist to prevent was precisely
that a signal nothing had subscribed to killed the process where it stood: a
double that "delivers a signal" by calling a handler would have agreed with the
broken code (docs/SPEC.md §6, CLAUDE.md invariant 5 -- nothing here is real
tenant data).

Synthetic throughout.
"""

from __future__ import annotations

import asyncio
import os
import signal
import time
from dataclasses import dataclass

import pytest

from ocsf_connector.runner.loop import RunStats, run
from ocsf_connector.runner.shutdown import Shutdown, stop_on_signals
from ocsf_connector.sources.base import Page
from ocsf_connector.state.memory import InMemoryStateStore
from tests.doubles import CountingMapper, RecordingSink, ScriptedSource, chain

STREAM = "okta-system-log"


async def until_requested(shutdown: Shutdown, timeout: float = 5.0) -> int | None:
    """Wait for a signal the loop has not processed yet.

    Signal delivery reaches asyncio through its wakeup pipe, so it lands on a
    later iteration of the event loop rather than at the next `await` -- a bare
    ``sleep(0)`` observes nothing and would make these tests flake in the
    direction of passing.
    """
    deadline = time.monotonic() + timeout
    while shutdown.requested() is None and time.monotonic() < deadline:
        await asyncio.sleep(0.01)
    return shutdown.requested()


# --- the signal seam ---------------------------------------------------------


async def test_sigterm_asks_for_a_stop_rather_than_killing_the_process() -> None:
    """The bug this file exists for: SIGTERM is what a container runtime, a pod
    eviction and systemd all send, and nothing had subscribed to it -- so a stop
    ran no cleanup, produced no exit code and said nothing."""
    async with stop_on_signals() as shutdown:
        os.kill(os.getpid(), signal.SIGTERM)

        assert await until_requested(shutdown) == signal.SIGTERM


async def test_a_stop_wakes_a_sleeping_tail_instead_of_waiting_out_the_poll() -> None:
    """A tail spends nearly all its life asleep between polls. Waiting out the
    interval would make `poll_seconds` -- a number chosen for the rate limit --
    decide how long an operator waits before reaching for a harder signal."""
    async with stop_on_signals() as shutdown:
        sleeping = asyncio.create_task(shutdown.sleep(30.0))
        await asyncio.sleep(0)
        os.kill(os.getpid(), signal.SIGTERM)

        # Fails by timing out at two seconds rather than sleeping for thirty.
        await asyncio.wait_for(sleeping, timeout=2.0)


async def test_an_unstopped_sleep_still_waits() -> None:
    """The contrast case: without a signal this is an ordinary sleep, and a
    version that returned immediately would poll Okta as fast as it can."""
    shutdown = Shutdown()
    started = time.monotonic()

    await shutdown.sleep(0.05)

    assert time.monotonic() - started >= 0.05


async def test_the_first_signal_is_the_one_reported() -> None:
    """The exit code names what actually stopped the run, so a later signal must
    not overwrite it -- 143 when a supervisor asked, 130 when a human did."""
    shutdown = Shutdown()

    shutdown.request(signal.SIGINT)
    shutdown.request(signal.SIGTERM)

    assert shutdown.requested() == signal.SIGINT


async def test_a_second_signal_cancels_rather_than_waiting_for_the_page() -> None:
    """Asking twice means not waiting for an in-flight fetch. Cancelling still
    unwinds through the mode's `finally`, so the store closes -- the part a bare
    SIGTERM used to skip -- and the open batch replays like any abrupt death."""

    async def wedged() -> None:
        async with stop_on_signals() as shutdown:
            os.kill(os.getpid(), signal.SIGTERM)
            assert await until_requested(shutdown) == signal.SIGTERM
            os.kill(os.getpid(), signal.SIGTERM)
            await asyncio.sleep(30.0)  # the fetch that will not come back

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(asyncio.create_task(wedged()), timeout=5.0)


async def test_the_default_disposition_comes_back_afterwards() -> None:
    """A backfill that finishes hands the process back the way it found it: a
    handler left installed would make the *next* Ctrl-C do nothing visible."""
    async with stop_on_signals():
        assert signal.getsignal(signal.SIGTERM) is not signal.SIG_DFL

    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


# --- what the loop does with it ----------------------------------------------


@dataclass(slots=True)
class StopAfter:
    """Asks for a stop once ``pages`` have been fetched.

    Shaped like the real thing -- a callable returning a signal number or None
    -- so the loop cannot tell it apart from a delivered signal.
    """

    source: ScriptedSource
    pages: int
    signum: int = int(signal.SIGTERM)

    def __call__(self) -> int | None:
        return self.signum if len(self.source.fetched) >= self.pages else None


async def test_a_stopped_run_returns_what_it_did() -> None:
    """The other half of the bug: a tail interrupted through its current await
    had no way to report anything, so the summary was unreachable in the only
    mode that runs long enough to want one.

    The chain here is a polling one -- every page carries a next link -- so a
    loop that ignored the stop would run past the end of the script rather than
    hanging the suite.
    """
    source = ScriptedSource(chain([["a1"], ["b1"], ["c1"]], terminal=False))

    stats = await run(
        source=source,
        mapper=CountingMapper(),
        sink=RecordingSink(),
        store=InMemoryStateStore(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
        stop_signal=StopAfter(source, pages=2),
    )

    assert stats.stopped_by == signal.SIGTERM
    assert stats.pages == 2, "the page in flight when the signal arrived still finished"
    assert stats.written == 2
    assert not stats.exhausted, "a stopped tail has not finished a range"


async def test_a_run_that_ends_on_its_own_was_not_stopped() -> None:
    """The contrast case: `stopped_by` decides the exit code, so a completed
    backfill reporting one would tell a supervisor it was killed."""
    source = ScriptedSource(chain([["a1"]]))

    stats = await run(
        source=source,
        mapper=CountingMapper(),
        sink=RecordingSink(),
        store=InMemoryStateStore(),
        stream=STREAM,
        start=lambda: source.start_backfill("2026-09-05T00:00:00Z", "2026-09-06T00:00:00Z"),
        stop_signal=lambda: None,
    )

    assert stats.exhausted and stats.stopped_by is None


async def test_a_stop_leaves_the_open_batch_to_replay_rather_than_flushing_it() -> None:
    """Stopping deliberately does *not* flush what is buffered.

    The cursor moves only after an acknowledged flush (§5), so an unflushed
    batch replays from the committed cursor on the next start -- the same path a
    kill takes, verified live. Flushing here would buy back one poll's worth of
    re-fetching at the price of a second copy of the flush/ack/commit order in
    the one file that has it.
    """
    pages = chain([["a1"], ["b1"]], terminal=False)
    source = ScriptedSource(pages)
    sink = RecordingSink(flush_every_page=False)
    store = InMemoryStateStore()

    stopped = await run(
        source=source,
        mapper=CountingMapper(),
        sink=sink,
        store=store,
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
        stop_signal=StopAfter(source, pages=2),
    )

    assert stopped.commits == 0 and sink.objects == {}
    assert await store.get_cursor(STREAM) is None, "nothing acknowledged, nothing committed"

    # Restart: the successor opens where the stopped run did and delivers every
    # event exactly once.
    successor = ScriptedSource(pages)
    await run(
        source=successor,
        mapper=CountingMapper(),
        sink=RecordingSink(),
        store=store,
        stream=STREAM,
        start=lambda: successor.start_tail("2026-09-05T00:00:00Z"),
        stop_signal=StopAfter(successor, pages=2),
    )

    assert successor.fetched[0] == source.fetched[0], "resumed from the same cursor"


async def test_a_real_signal_ends_a_real_idle_tail() -> None:
    """The whole mechanism at once: a signal nobody polls for, a loop that would
    otherwise never return, and stats that come back anyway.

    The page below is what a live idle tail actually sees -- verified against an
    org on 2026-09-21 -- an empty page whose next link is the URL that asked for
    it (§2.2). So this loop has no ending of its own, and the two-second timeout
    is the assertion: without the stop it runs until pytest is killed.
    """
    idling = ScriptedSource({"c0": Page(records=[], next_cursor="c0")})

    async def tail_until_signalled() -> RunStats:
        async with stop_on_signals() as shutdown:
            asyncio.get_running_loop().call_later(0.05, os.kill, os.getpid(), signal.SIGTERM)
            return await run(
                source=idling,
                mapper=CountingMapper(),
                sink=RecordingSink(),
                store=InMemoryStateStore(),
                stream=STREAM,
                start=lambda: idling.start_tail("2026-09-05T00:00:00Z"),
                on_idle=lambda: shutdown.sleep(30.0),
                stop_signal=shutdown.requested,
            )

    stats = await asyncio.wait_for(tail_until_signalled(), timeout=2.0)

    assert stats.stopped_by == signal.SIGTERM
    assert stats.pages >= 1 and not stats.exhausted


# --- saying it is alive ------------------------------------------------------


async def test_every_page_reports_progress_including_the_empty_ones() -> None:
    """§7, verified live: a healthy idle tail commits nothing, so cursor age and
    commit lag both stand still while the loop is perfectly healthy. Reporting
    only on pages that carried events would go silent exactly when an operator
    most wants to know the difference between idle and wedged."""
    source = ScriptedSource(chain([["a1"], [], ["b1"]], terminal=False))
    seen: list[RunStats] = []

    await run(
        source=source,
        mapper=CountingMapper(),
        sink=RecordingSink(),
        store=InMemoryStateStore(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
        stop_signal=StopAfter(source, pages=3),
        on_progress=seen.append,
    )

    assert [stats.pages for stats in seen] == [1, 2, 3]
    assert [stats.written for stats in seen] == [1, 1, 2], "the empty page reported too"


async def test_progress_is_reported_before_the_sleep_not_after() -> None:
    """An operator reads the line for the page that just landed. Reporting after
    the idle sleep would date every line by one poll interval."""
    source = ScriptedSource(chain([[]], terminal=False))
    order: list[str] = []

    async def note_idle() -> None:
        order.append("idle")

    await run(
        source=source,
        mapper=CountingMapper(),
        sink=RecordingSink(),
        store=InMemoryStateStore(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
        on_idle=note_idle,
        stop_signal=StopAfter(source, pages=1),
        on_progress=lambda stats: order.append("progress"),
    )

    assert order == ["progress", "idle"]
