"""Stopping on purpose.

A tail never returns on its own (§2.2), so *every* tail run ends by being
stopped -- which makes shutdown part of the normal path rather than an error
path, and worth the same care. Two facts decided the design here, both observed
against a live org on 2026-09-21:

**SIGTERM was not handled at all.** Python's default disposition kills the
process outright, so a container stop, a pod eviction or a systemd restart ran
no cleanup: no store close, no exit code, no summary. The mode that runs forever
handled only the signal a human at a terminal sends. Nothing was lost -- the
cursor commits after an acknowledged flush, so an abrupt death replays the open
batch (§5.2) -- but the clean close was.

**Interrupting the loop is not the same as stopping it.** Raising through
whatever await happened to be running leaves the runner with no way to report
what it did, which is why the run summary was unreachable in the only mode that
runs long enough to want one. So a signal sets a flag the loop reads between
pages, and the loop returns normally.

A second signal cancels instead, because an operator who asks twice is not
waiting for an in-flight fetch. That lands like a crash -- possibly inside a
flush -- which is exactly the case the commit order already covers.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal
from collections.abc import AsyncIterator, Iterable

STOP_SIGNALS: tuple[signal.Signals, ...] = (signal.SIGINT, signal.SIGTERM)
"""What a stop looks like: Ctrl-C from a human, SIGTERM from everything else."""


class Shutdown:
    """A request to stop, readable from inside the run loop.

    Carries the signal number rather than a bare flag so the caller can exit
    128+n -- 130 for SIGINT, 143 for SIGTERM -- which is what a supervisor reads
    to tell "asked to stop" from "fell over".
    """

    __slots__ = ("_event", "_signum")

    def __init__(self) -> None:
        self._event = asyncio.Event()
        self._signum: int | None = None

    def request(self, signum: int) -> None:
        """Ask for a stop. The first signal wins; later ones change nothing."""
        if self._signum is None:
            self._signum = signum
            self._event.set()

    def requested(self) -> int | None:
        """The signal that asked this run to stop, or ``None`` to keep going.

        Shaped as a callable because that is what the runner takes: the loop
        reports the value in its stats without interpreting it, and a test can
        pass any function of the same shape.
        """
        return self._signum

    async def sleep(self, seconds: float) -> None:
        """Sleep, but no longer than it takes for a stop to arrive.

        A tail spends nearly all of its life here, so a plain ``asyncio.sleep``
        would make the poll interval the floor on how long a shutdown takes --
        and `poll_seconds` is tuned for the rate limit, not for how long an
        operator will wait before reaching for a harder signal.
        """
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._event.wait(), seconds)


@contextlib.asynccontextmanager
async def stop_on_signals(
    signals: Iterable[signal.Signals] = STOP_SIGNALS,
) -> AsyncIterator[Shutdown]:
    """Route ``signals`` into a :class:`Shutdown` for the duration of the block.

    Uses ``loop.add_signal_handler`` rather than ``signal.signal`` so delivery
    lands as an ordinary callback on the event loop instead of raising through
    whichever await was running. The handlers are removed on the way out, which
    restores the default disposition -- a process that survives this block gets
    its Ctrl-C back.

    POSIX only, deliberately: the deployment shape is a container and a Job
    (§6), and ``add_signal_handler`` is unimplemented on Windows. Failing loudly
    there beats a silent fallback that looks like it handles signals.
    """
    shutdown = Shutdown()
    loop = asyncio.get_running_loop()
    # Captured now, while we are still on the task that will be running the
    # loop. A signal handler runs outside any task, so it cannot ask.
    task = asyncio.current_task()
    installed: list[signal.Signals] = []

    def arrive(signum: signal.Signals) -> None:
        if shutdown.requested() is not None:
            # Asked twice. Stop waiting for the current page and cancel, which
            # still unwinds through the mode's `finally` and closes the store --
            # the part SIGTERM used to skip. An in-flight flush cancelled here
            # replays on the next start, the same as any other abrupt death.
            if task is not None:
                task.cancel()
            return
        shutdown.request(signum)

    try:
        for signum in signals:
            loop.add_signal_handler(signum, arrive, signum)
            installed.append(signum)
        yield shutdown
    finally:
        for signum in installed:
            loop.remove_signal_handler(signum)
