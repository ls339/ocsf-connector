"""State seam: resume position and replay dedup.

Two pieces of state with very different jobs, deliberately kept separate:

``cursor``      the only control state. Opaque, committed after sink ack.
``seen``        bounded, TTL'd set of source event ids that absorbs duplicates
                the *source* delivers (Okta documents that paginating a log
                query "may lead to skipped or duplicated events").

``last_published`` is recorded but is NOT resume state -- Okta polling queries
are ordered by internal persistence time and may return events out of order by
``published``, so a timestamp watermark drops late-persisted events silently.
It exists only to compute ingest lag. See docs/SPEC.md §2.1 and §5.

The cursor and the seen-set are advanced by a single :meth:`StateStore.commit`
rather than by two separate calls. Two calls would open a third crash window
between them; one call makes the ordering structural instead of argued. See
docs/SPEC.md §5.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from ocsf_connector.domain import Cursor


class StateStore(Protocol):
    async def get_cursor(self, stream: str) -> Cursor | None:
        """Resume position, or ``None`` if this stream has never committed."""
        ...

    async def commit(
        self,
        stream: str,
        cursor: Cursor | None,
        uids: Sequence[str],
        mapping_version: str,
    ) -> None:
        """Atomically advance the resume position and mark ``uids`` delivered.

        MUST only be called after the sink has acknowledged every event that
        preceded ``cursor``. This ordering is the connector's core invariant.

        Atomic means: a crash during this call leaves *neither* the cursor nor
        the uids recorded, never one without the other. An implementation that
        cannot guarantee that has not implemented this protocol.

        ``cursor`` is ``None`` only at the end of a bounded (backfill) range.
        ``mapping_version`` records the mapping-table revision that produced the
        batch being committed, so any write can be traced to its rules.

        A commit also stamps the stream caught up, in the same transaction: see
        :meth:`mark_caught_up`.
        """
        ...

    async def mark_caught_up(self, stream: str) -> None:
        """Record that the stream was keeping up with the source, as of now.

        The runner calls this on an empty page with nothing buffered -- proof
        that nothing undelivered existed past the committed cursor -- and a
        commit does the same implicitly. A healthy idle tail commits nothing for
        hours (docs/SPEC.md §7), so a commit alone would make an idle stream
        look abandoned.

        Read back at startup to tell whether a resumed stream was stopped long
        enough for Okta's retention to have eaten what it missed (§2.6). A
        stream that has never committed has nothing to stamp, and this is then a
        no-op.
        """
        ...

    async def filter_unseen(self, uids: Sequence[str]) -> list[str]:
        """Return the subset not already delivered: unique, order-preserving."""
        ...

    async def get_mapping_version(self, stream: str) -> str | None:
        """Mapping revision that produced the last committed batch.

        Read on startup to detect that the mapping table changed underneath a
        resumed stream. Never used to decide *where* to resume.
        """
        ...

    async def record_published(self, stream: str, published_ms: int) -> None:
        """Observability only. Never read back to determine a resume point."""
        ...

    async def purge_expired(self) -> int:
        """Drop seen-set entries past their TTL. Returns how many were removed.

        Here, in the runner's protocol, because the runner is what calls it.
        Expired rows are already ignored by :meth:`filter_unseen`, so this
        changes no behavior -- but nothing else reclaims them, and a tail does
        not restart. Left uncalled, the seen-set grows for the life of the
        stream at up to a thousand rows a page, with its index alongside.
        """
        ...


class ManagedStateStore(StateStore, Protocol):
    """What an *owner* of the store needs, beyond what the runner uses.

    Kept separate deliberately. :class:`StateStore` is the runner's dependency
    and names only what `runner/loop.py` actually calls; a single protocol
    carrying everything would make the loop demand methods it never touches, and
    would stop a wrapper that forwards the loop's surface -- like the crash
    double in the test suite -- from satisfying it.

    These belong to whoever owns the store's lifecycle: the composition root,
    operational tooling, and the tests that hold both implementations to the
    same promises. That last one is why they are a protocol at all rather than
    an informal convention. Both implementations having them is what lets the
    shared suite drop the ``isinstance`` checks it used to need, and an
    assertion skipped by such a check is an assertion that never ran.
    """

    async def get_last_published(self, stream: str) -> int | None:
        """Observability only. Never read back to determine a resume point."""
        ...

    def has_committed(self, stream: str) -> bool:
        """Tell "range finished" from "never started" -- both of which read as a
        ``None`` cursor (docs/SPEC.md §5.3)."""
        ...

    async def caught_up_age(self, stream: str) -> float | None:
        """Seconds since the stream was last stamped caught up, on this store's
        own clock, or ``None`` if it never was.

        An age rather than an instant so the in-memory store's monotonic
        timeline never has to be compared with anyone's wall clock.
        """
        ...

    def close(self) -> None:
        """Release whatever this implementation holds.

        A no-op is a valid implementation: an in-memory store has nothing to
        release, and an owner should not have to ask which kind it holds.
        """
        ...
