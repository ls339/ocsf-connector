"""SQLite :class:`StateStore`: the cursor and the seen-set, durably.

The in-memory store cannot demonstrate what docs/SPEC.md §5.1 actually demands --
that a crash between the sink's acknowledgement and the commit leaves *neither*
the cursor nor the seen-set behind. Its state dies with the process, so atomicity
is free there, and free is not the same as proven. Here it is a real transaction
over a real file, and the crash that matters is a connection that closes with a
transaction still open.

Three details are load-bearing:

``synchronous=FULL``
    A commit that has not reached disk can lie about what the sink acknowledged,
    which is the one thing this connector must never do. WAL plus FULL means a
    committed transaction survives power loss. It costs an fsync per commit --
    once per flushed batch, not once per event (§4.1).

``asyncio.Lock``
    ``sqlite3.threadsafety`` is 3, so a connection may be shared across threads,
    but a connection holds one transaction at a time: two overlapping
    ``BEGIN IMMEDIATE`` calls on it raise "cannot start a transaction within a
    transaction". Every transaction here runs under the lock, one at a time.

Wall clock, not monotonic
    The in-memory store defaults to ``time.monotonic``, which is right when state
    dies with the process. A TTL that outlives the process cannot: monotonic
    clocks restart when the process does, so a restart would resurrect expired
    uids or expire live ones. This store uses ``time.time``.
"""

from __future__ import annotations

import asyncio
import sqlite3
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from ocsf_connector.domain import Cursor

DEFAULT_TTL_SECONDS = 24 * 60 * 60

PARAMETER_CHUNK = 400
"""Keep ``uid IN (...)`` well under SQLite's variable limit on any build."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS streams (
    stream            TEXT PRIMARY KEY,
    cursor            TEXT,
    committed         INTEGER NOT NULL DEFAULT 0,
    mapping_version   TEXT,
    last_published_ms INTEGER
);
CREATE TABLE IF NOT EXISTS seen (
    uid        TEXT PRIMARY KEY,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS seen_expires_at ON seen (expires_at);
"""


class SqliteStateStore:
    """Implements :class:`~ocsf_connector.state.store.StateStore` over one file.

    ``committed`` is a column rather than an inference from ``cursor IS NULL``,
    because a finished bounded range commits a ``None`` cursor and must stay
    distinguishable from a stream that never started (§5.3).
    """

    def __init__(
        self,
        path: str | Path,
        *,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = str(path)
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._lock = asyncio.Lock()
        # Connecting and creating the schema is synchronous on purpose: it is a
        # local file opened once at startup, and it keeps construction ordinary.
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(SCHEMA)
        # Read once at open so has_committed can stay synchronous; a reopened
        # handle recovers it from the file, which is what makes it survive.
        self._committed = {
            str(row[0])
            for row in self._conn.execute("SELECT stream FROM streams WHERE committed = 1")
        }

    async def get_cursor(self, stream: str) -> Cursor | None:
        row = await self._fetch("SELECT cursor FROM streams WHERE stream = ?", (stream,))
        if row is None or row[0] is None:
            return None
        return str(row[0])

    async def commit(
        self,
        stream: str,
        cursor: Cursor | None,
        uids: Sequence[str],
        mapping_version: str,
    ) -> None:
        """Advance the cursor and mark ``uids`` delivered, in one transaction.

        One transaction is the whole point: a crash during it leaves neither
        write, so a replayed batch cannot arrive with a cursor that has moved
        past it (§5.1).
        """
        expires_at = self.clock() + self.ttl_seconds
        rows = [(uid, expires_at) for uid in uids]

        def write() -> None:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    """
                    INSERT INTO streams (stream, cursor, committed, mapping_version)
                    VALUES (?, ?, 1, ?)
                    ON CONFLICT(stream) DO UPDATE SET
                        cursor = excluded.cursor,
                        committed = 1,
                        mapping_version = excluded.mapping_version
                    """,
                    (stream, cursor, mapping_version),
                )
                self._conn.executemany(
                    "INSERT OR REPLACE INTO seen (uid, expires_at) VALUES (?, ?)", rows
                )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

        async with self._lock:
            await asyncio.to_thread(write)
        self._committed.add(stream)

    async def filter_unseen(self, uids: Sequence[str]) -> list[str]:
        """The subset not already delivered: unique, order-preserving."""
        now = self.clock()
        unique = list(dict.fromkeys(uids))

        def query() -> set[str]:
            found: set[str] = set()
            for start in range(0, len(unique), PARAMETER_CHUNK):
                chunk = unique[start : start + PARAMETER_CHUNK]
                placeholders = ",".join("?" * len(chunk))
                found.update(
                    str(row[0])
                    for row in self._conn.execute(
                        f"SELECT uid FROM seen WHERE expires_at > ? AND uid IN ({placeholders})",
                        (now, *chunk),
                    )
                )
            return found

        if not unique:
            return []
        async with self._lock:
            delivered = await asyncio.to_thread(query)
        return [uid for uid in unique if uid not in delivered]

    async def get_mapping_version(self, stream: str) -> str | None:
        row = await self._fetch("SELECT mapping_version FROM streams WHERE stream = ?", (stream,))
        if row is None or row[0] is None:
            return None
        return str(row[0])

    async def record_published(self, stream: str, published_ms: int) -> None:
        """Observability only, and it only moves forward (§5.3)."""

        def write() -> None:
            self._conn.execute(
                """
                INSERT INTO streams (stream, last_published_ms) VALUES (?, ?)
                ON CONFLICT(stream) DO UPDATE SET
                    last_published_ms = MAX(
                        COALESCE(last_published_ms, 0), excluded.last_published_ms
                    )
                """,
                (stream, published_ms),
            )

        async with self._lock:
            await asyncio.to_thread(write)

    async def get_last_published(self, stream: str) -> int | None:
        """Never used to resume. Exists so ingest lag has something to read."""
        row = await self._fetch("SELECT last_published_ms FROM streams WHERE stream = ?", (stream,))
        if row is None or row[0] is None:
            return None
        return int(row[0])

    def has_committed(self, stream: str) -> bool:
        """Not part of the protocol: lets a caller tell "range finished" from
        "never started", both of which read as a ``None`` cursor (§5.3)."""
        return stream in self._committed

    async def purge_expired(self) -> int:
        def delete() -> int:
            cursor = self._conn.execute("DELETE FROM seen WHERE expires_at <= ?", (self.clock(),))
            return int(cursor.rowcount)

        async with self._lock:
            return await asyncio.to_thread(delete)

    def close(self) -> None:
        self._conn.close()

    async def _fetch(self, sql: str, params: tuple[Any, ...]) -> tuple[Any, ...] | None:
        def read() -> tuple[Any, ...] | None:
            row = self._conn.execute(sql, params).fetchone()
            return tuple(row) if row is not None else None

        async with self._lock:
            return await asyncio.to_thread(read)
