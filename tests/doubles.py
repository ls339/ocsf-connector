"""Test doubles for the runner.

All data here is synthetic: invented uuids, an invented org, no real tenant,
user, email address or IP appears anywhere (CLAUDE.md invariant 5).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from ocsf_connector.mapping.base import OcsfEvent
from ocsf_connector.sources.base import Cursor, Page
from ocsf_connector.state.store import StateStore

BASE_TIME_MS = 1_756_900_000_000


class SimulatedCrash(Exception):
    """Stands in for the process dying. Raised where a kill -9 would land."""


def record(
    uid: str, *, offset_ms: int = 0, event_type: str = "user.session.start"
) -> dict[str, Any]:
    return {
        "uuid": uid,
        "published": BASE_TIME_MS + offset_ms,
        "eventType": event_type,
        "outcome": {"result": "SUCCESS"},
    }


def chain(pages: Sequence[Sequence[str]], *, terminal: bool = True) -> dict[Cursor, Page]:
    """Build a cursor-addressed page chain: ``c0`` -> ``c1`` -> ... .

    ``terminal`` mirrors the two query modes: a bounded query's last page has no
    ``next``, a polling query's always does (docs/SPEC.md §2.1).
    """
    built: dict[Cursor, Page] = {}
    for index, uids in enumerate(pages):
        last = index == len(pages) - 1
        next_cursor = None if (last and terminal) else f"c{index + 1}"
        built[f"c{index}"] = Page(
            records=[record(uid, offset_ms=index * 1000) for uid in uids],
            next_cursor=next_cursor,
        )
    return built


@dataclass(slots=True)
class ScriptedSource:
    """Replays a fixed page chain. Refetching a cursor returns the same page,
    which is what makes a real cursor safe to replay after a crash."""

    pages: dict[Cursor, Page]
    name: str = "scripted"
    fetched: list[Cursor] = field(default_factory=list)

    async def start_tail(self, since: str) -> Cursor:
        return "c0"

    async def start_backfill(self, since: str, until: str) -> Cursor:
        return "c0"

    async def fetch(self, cursor: Cursor) -> Page:
        self.fetched.append(cursor)
        return self.pages[cursor]


@dataclass(slots=True)
class CountingMapper:
    """Identity mapping. Counts calls so a test can assert that dedup runs
    *after* mapping, which is what keeps the drift counter alive on replay."""

    ocsf_version: str = "1.3.0"
    mapping_version: str = "okta-2026.09.01"
    seen_records: list[str] = field(default_factory=list)

    def map(self, record: dict[str, Any]) -> OcsfEvent:
        uid = str(record["uuid"])
        self.seen_records.append(uid)
        return OcsfEvent(
            class_uid=3002,
            time_ms=int(record["published"]),
            uid=uid,
            body={"metadata": {"uid": uid, "version": self.ocsf_version}, "unmapped": record},
        )


@dataclass(slots=True)
class RecordingSink:
    """Models an object store: ``flush`` PUTs the buffer at ``batch_key``, so
    re-flushing the same key overwrites rather than appending a second object."""

    name: str = "recording"
    flush_every_page: bool = True
    buffer: list[OcsfEvent] = field(default_factory=list)
    objects: dict[str, list[OcsfEvent]] = field(default_factory=dict)
    flushes: list[str] = field(default_factory=list)

    async def write(self, events: list[OcsfEvent]) -> None:
        self.buffer.extend(events)

    async def flush(self, batch_key: str) -> None:
        self.objects[batch_key] = list(self.buffer)
        self.buffer.clear()
        self.flushes.append(batch_key)

    @property
    def should_flush(self) -> bool:
        return self.flush_every_page

    def delivered(self) -> list[str]:
        return [event.uid for obj in self.objects.values() for event in obj]


@dataclass(slots=True)
class FailingSink(RecordingSink):
    """A sink whose durable write fails. The runner must not commit."""

    async def flush(self, batch_key: str) -> None:
        raise OSError("object store unavailable")


@dataclass(slots=True)
class CrashOnCommit:
    """Wraps a store and dies on the Nth commit, before it records anything --
    i.e. in the gap between the sink ack and the cursor commit."""

    inner: StateStore
    crash_on: int
    commits: int = 0

    async def get_cursor(self, stream: str) -> Cursor | None:
        return await self.inner.get_cursor(stream)

    async def commit(
        self,
        stream: str,
        cursor: Cursor | None,
        uids: Sequence[str],
        mapping_version: str,
    ) -> None:
        self.commits += 1
        if self.commits == self.crash_on:
            raise SimulatedCrash(f"died committing {cursor!r}")
        await self.inner.commit(stream, cursor, uids, mapping_version)

    async def filter_unseen(self, uids: Sequence[str]) -> list[str]:
        return await self.inner.filter_unseen(uids)

    async def get_mapping_version(self, stream: str) -> str | None:
        return await self.inner.get_mapping_version(stream)

    async def record_published(self, stream: str, published_ms: int) -> None:
        await self.inner.record_published(stream, published_ms)


@dataclass(slots=True)
class DriftingStartSource(ScriptedSource):
    """A source whose *opening* cursor moves between calls.

    This is what tail looks like when its ``since`` is computed from ``now()`` at
    startup instead of read from config. Each new opening cursor aliases to the
    same first page -- the vendor returns the same events either way; the only
    thing that changed is the key the batch is addressed by. See docs/SPEC.md
    §5.2.
    """

    starts: int = 0

    async def start_tail(self, since: str) -> Cursor:
        self.starts += 1
        alias = f"s{self.starts}"
        self.pages[alias] = self.pages["c0"]
        return alias
