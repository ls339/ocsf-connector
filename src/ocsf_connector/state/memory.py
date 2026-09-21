"""In-memory :class:`StateStore`, for tests and single-process backfills.

Loses everything on exit, which makes it useless in production and ideal for
asserting the commit-order invariant: a test can drop the process's *runner*
while keeping the store, which is exactly the crash this connector is designed
around. See docs/SPEC.md §5.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ocsf_connector.domain import Cursor

DEFAULT_TTL_SECONDS = 24 * 60 * 60


@dataclass(slots=True)
class _Stream:
    cursor: Cursor | None = None
    committed: bool = False
    """Distinguishes "never committed" from "committed a ``None`` cursor",
    which is how a completed bounded range is recorded."""
    mapping_version: str | None = None
    last_published_ms: int | None = None


@dataclass(slots=True)
class InMemoryStateStore:
    """Every mutation happens between awaits, so commits are atomic for free.

    A durable implementation has to work for this: the cursor write and the
    seen-set write must land in one transaction, or the protocol is violated.
    """

    ttl_seconds: float = DEFAULT_TTL_SECONDS
    clock: Callable[[], float] = time.monotonic
    _streams: dict[str, _Stream] = field(default_factory=dict)
    _seen: dict[str, float] = field(default_factory=dict)
    """uid -> expiry instant, on ``clock``'s timeline."""

    async def get_cursor(self, stream: str) -> Cursor | None:
        row = self._streams.get(stream)
        return row.cursor if row else None

    async def commit(
        self,
        stream: str,
        cursor: Cursor | None,
        uids: Sequence[str],
        mapping_version: str,
    ) -> None:
        row = self._streams.setdefault(stream, _Stream())
        expiry = self.clock() + self.ttl_seconds
        for uid in uids:
            self._seen[uid] = expiry
        row.cursor = cursor
        row.committed = True
        row.mapping_version = mapping_version

    async def filter_unseen(self, uids: Sequence[str]) -> list[str]:
        now = self.clock()
        fresh: list[str] = []
        within_batch: set[str] = set()
        for uid in uids:
            if uid in within_batch:
                continue
            expiry = self._seen.get(uid)
            if expiry is not None and expiry > now:
                continue
            within_batch.add(uid)
            fresh.append(uid)
        return fresh

    async def get_mapping_version(self, stream: str) -> str | None:
        row = self._streams.get(stream)
        return row.mapping_version if row else None

    async def record_published(self, stream: str, published_ms: int) -> None:
        row = self._streams.setdefault(stream, _Stream())
        if row.last_published_ms is None or published_ms > row.last_published_ms:
            row.last_published_ms = published_ms

    async def get_last_published(self, stream: str) -> int | None:
        """Never used to resume; ingest lag reads it.

        Its absence here was not harmless. The shared store suite guarded this
        assertion with ``isinstance(store, SqliteStateStore)``, so the claim
        that ``last_published`` only moves forward was never checked against
        this implementation at all -- the comparison in
        :meth:`record_published` could have been inverted and the suite would
        have stayed green.
        """
        row = self._streams.get(stream)
        return row.last_published_ms if row else None

    def has_committed(self, stream: str) -> bool:
        """Tell "range finished" from "never started", both of which read as a
        ``None`` cursor."""
        row = self._streams.get(stream)
        return row is not None and row.committed

    def close(self) -> None:
        """Nothing to release. Present so an owner can close any store without
        first asking which kind it is holding."""

    async def purge_expired(self) -> int:
        """Async to match the durable store, whose purge is a write that has to
        take the same lock as every other transaction."""
        now = self.clock()
        stale = [uid for uid, expiry in self._seen.items() if expiry <= now]
        for uid in stale:
            del self._seen[uid]
        return len(stale)
