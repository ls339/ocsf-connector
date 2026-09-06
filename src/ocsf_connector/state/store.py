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

from ocsf_connector.sources.base import Cursor


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
