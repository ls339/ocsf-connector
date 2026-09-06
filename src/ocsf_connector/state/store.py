"""State seam: resume position and replay dedup.

Two pieces of state with very different jobs, deliberately kept separate:

``cursor``      the only control state. Opaque, committed after sink ack.
``seen``        bounded, TTL'd set of source event ids that absorbs the replay
                a crash between ack and commit produces.

``last_published`` is recorded but is NOT resume state -- Okta polling queries
are ordered by internal persistence time and may return events out of order by
``published``, so a timestamp watermark drops late-persisted events silently.
It exists only to compute ingest lag. See docs/SPEC.md §2.1 and §5.
"""

from __future__ import annotations

from typing import Protocol

from ocsf_connector.sources.base import Cursor


class StateStore(Protocol):
    async def get_cursor(self, stream: str) -> Cursor | None:
        ...

    async def commit_cursor(self, stream: str, cursor: Cursor) -> None:
        """Durably record the resume position.

        MUST only be called after the sink has acknowledged every event that
        preceded this cursor. This ordering is the connector's core invariant.
        """
        ...

    async def filter_unseen(self, uids: list[str]) -> list[str]:
        """Return the subset not already delivered, preserving order."""
        ...

    async def mark_seen(self, uids: list[str]) -> None:
        """Record ids as delivered. Called after the sink ack, with the cursor
        commit, so that a crash before either replays both consistently."""
        ...

    async def record_published(self, stream: str, published_ms: int) -> None:
        """Observability only. Never read back to determine a resume point."""
        ...
