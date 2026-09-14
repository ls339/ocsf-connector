"""Amazon Security Lake sink: OCSF events out as partitioned Parquet.

The vendor requirements in docs/SPEC.md §4 are unusually specific, and each one
shows up here as a line of code rather than a comment: zstd, data pages of at
most 1 MB uncompressed, records sorted by time within an object, **one OCSF class
per object**, and the partition prefix Security Lake expects.

Two things are less obvious and matter more.

**``flush`` is addressed, not appended.** The batch is named by the cursor it
began at, hashed into the object key. Re-flushing a replayed batch rewrites the
same objects instead of adding more, which is what makes delivery
effectively-once across a crash in the ack->commit gap (§5.2). The hash is
required, not cosmetic: a cursor is an opaque URL and cannot be a path segment.

**The schema is half declared and half inferred.** The base-event columns every
OCSF record carries are declared with fixed Arrow types, so the Glue table's core
never drifts between objects. Class-specific objects -- ``user``, ``entity``,
``service`` and the rest -- are inferred from the batch, because OCSF classes do
not agree on them and pinning all six by hand would make every new mapped field a
schema edit. ``unmapped`` is a JSON string: its shape is by definition whatever
the vendor sent, which is not a thing a column type can describe.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from io import BytesIO

import pyarrow as pa
import pyarrow.parquet as pq

from ocsf_connector.mapping.base import OcsfEvent
from ocsf_connector.sinks.objects import ObjectStore

MAX_BYTES = 256 * 1024 * 1024
"""Security Lake's row-group ceiling, and this sink's buffer ceiling (§4)."""

MAX_SECONDS = 5 * 60.0
"""The floor on object cadence: more often than this only if files exceed 256 MB
(§4). It is also the replay window -- see the tradeoff in §4.1."""

DATA_PAGE_SIZE = 1024 * 1024
"""Data pages at most 1 MB uncompressed (§4)."""

PARQUET_VERSION = "2.6"
"""Security Lake accepts Parquet 1.x and 2.x (§4)."""

CLASS_SOURCES = {
    0: "base_event",
    3001: "account_change",
    3002: "authentication",
    3003: "authorize_session",
    3004: "entity_management",
    3005: "user_access",
    3006: "group_management",
}
"""One registered custom source per OCSF class (§4.1), named for the class as
OCSF 1.3.0 names it. A class absent here has no source to write to, which is a
packaging bug rather than a runtime condition."""

SPINE = pa.schema(
    [
        pa.field("time", pa.int64()),
        pa.field("class_uid", pa.int32()),
        pa.field("category_uid", pa.int32()),
        pa.field("activity_id", pa.int32()),
        pa.field("type_uid", pa.int64()),
        pa.field("severity_id", pa.int32()),
        pa.field("status_id", pa.int32()),
        pa.field("status", pa.string()),
        pa.field("status_detail", pa.string()),
        pa.field("message", pa.string()),
        pa.field(
            "metadata",
            pa.struct(
                [
                    pa.field("version", pa.string()),
                    pa.field("uid", pa.string()),
                    pa.field("original_time", pa.string()),
                    pa.field(
                        "product",
                        pa.struct(
                            [pa.field("name", pa.string()), pa.field("vendor_name", pa.string())]
                        ),
                    ),
                    pa.field("labels", pa.list_(pa.string())),
                ]
            ),
        ),
        pa.field("unmapped", pa.string()),
    ]
)
"""Declared once, identical in every object, whatever the class."""


@dataclass(slots=True)
class SecurityLakeSink:
    """Implements :class:`~ocsf_connector.sinks.base.Sink`.

    ``account_id`` is ``external_{okta_org_id}``: Okta events belong to no AWS
    account, and AWS recommends exactly this form for that case (§4.1).
    """

    store: ObjectStore
    source_name: str
    region: str
    account_id: str
    name: str = "security-lake"
    max_bytes: int = MAX_BYTES
    max_seconds: float = MAX_SECONDS
    clock: Callable[[], float] = time.time
    _buffer: list[OcsfEvent] = field(default_factory=list, init=False)
    _buffered_bytes: int = field(default=0, init=False)
    _opened_at: float | None = field(default=None, init=False)

    async def write(self, events: list[OcsfEvent]) -> None:
        """Buffer. Nothing is durable until :meth:`flush`."""
        if not events:
            return
        if self._opened_at is None:
            self._opened_at = self.clock()
        self._buffer.extend(events)
        self._buffered_bytes += sum(_estimate_bytes(event) for event in events)

    @property
    def should_flush(self) -> bool:
        if not self._buffer:
            return False
        if self._buffered_bytes >= self.max_bytes:
            return True
        opened_at = self._opened_at
        return opened_at is not None and self.clock() - opened_at >= self.max_seconds

    async def flush(self, batch_key: str) -> None:
        """Write the buffer as Parquet objects, one per (class, event day).

        Returns only once every object is durable; that return is what licenses
        the runner to commit its cursor (§5).
        """
        if not self._buffer:
            return

        digest = hashlib.sha256(batch_key.encode("utf-8")).hexdigest()[:32]
        for (class_uid, event_day), events in _bucket(self._buffer).items():
            body = _parquet_bytes(events)
            await self.store.put(self._key(class_uid, event_day, digest), body)

        self._buffer.clear()
        self._buffered_bytes = 0
        self._opened_at = None

    def _key(self, class_uid: int, event_day: str, digest: str) -> str:
        """The prefix Security Lake requires (§4), one source per class (§4.1).

        ``digest`` stands in for the cursor the batch began at: stable across a
        replay, so the replay overwrites, and path-safe, which an opaque URL is
        not (§5.2).
        """
        source = f"{self.source_name}_{CLASS_SOURCES[class_uid]}"
        return (
            f"ext/{source}"
            f"/region={self.region}"
            f"/accountId={self.account_id}"
            f"/eventDay={event_day}"
            f"/{digest}.parquet"
        )


def _bucket(events: Iterable[OcsfEvent]) -> dict[tuple[int, str], list[OcsfEvent]]:
    """Group by class and UTC event day -- the two things that decide an object.

    One class per object is a vendor requirement; one day per object is what the
    ``eventDay`` partition means (§4).
    """
    buckets: dict[tuple[int, str], list[OcsfEvent]] = {}
    for event in events:
        key = (event.class_uid, _event_day(event.time_ms))
        buckets.setdefault(key, []).append(event)
    return buckets


def _event_day(time_ms: int) -> str:
    return datetime.fromtimestamp(time_ms / 1000, UTC).strftime("%Y%m%d")


def _parquet_bytes(events: Sequence[OcsfEvent]) -> bytes:
    table = _table(sorted(events, key=lambda event: event.time_ms))
    buffer = BytesIO()
    pq.write_table(
        table,
        buffer,
        compression="zstd",
        data_page_size=DATA_PAGE_SIZE,
        row_group_size=len(events) or None,
        version=PARQUET_VERSION,
    )
    return buffer.getvalue()


def _table(events: Sequence[OcsfEvent]) -> pa.Table:
    rows = [_row(event) for event in events]
    columns: list[pa.Array] = []
    fields: list[pa.Field] = []

    for spine_field in SPINE:
        columns.append(pa.array([row.get(spine_field.name) for row in rows], type=spine_field.type))
        fields.append(spine_field)

    for name in sorted({key for row in rows for key in row} - set(SPINE.names)):
        values = [row.get(name) for row in rows]
        if all(value is None for value in values):
            # An all-null column infers Arrow's null type, which lands in the
            # Glue table as a column nothing can query. Better absent.
            continue
        array = pa.array(values)
        columns.append(array)
        fields.append(pa.field(name, array.type))

    return pa.Table.from_arrays(columns, schema=pa.schema(fields))


def _row(event: OcsfEvent) -> dict[str, object]:
    row = dict(event.body)
    # Whatever the vendor sent that the mapping did not claim. Its shape is not a
    # thing a column type can describe, so it travels as JSON (§3.3).
    row["unmapped"] = json.dumps(row.get("unmapped") or {}, sort_keys=True)
    return row


def _estimate_bytes(event: OcsfEvent) -> int:
    """Roughly what the event costs uncompressed.

    Deliberately an estimate: the exact figure is only knowable after encoding,
    and the flush trigger it feeds is a cadence guide, not an accounting record.
    """
    return len(json.dumps(event.body, default=str))
