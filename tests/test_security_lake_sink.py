"""The Security Lake sink: layout, Parquet shape, and idempotent flush.

Security Lake's requirements are specific enough that "it wrote a file" proves
nothing -- an object with the wrong prefix, the wrong codec, or two classes in it
is one Security Lake will not ingest, and it fails silently in their pipeline
rather than loudly in ours. So these read the bytes back.

Synthetic throughout (CLAUDE.md invariant 5).
"""

from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
import pytest

from ocsf_connector.mapping.base import OcsfEvent
from ocsf_connector.mapping.okta import OktaOcsfMapper
from ocsf_connector.sinks.objects import LocalObjectStore
from ocsf_connector.sinks.security_lake import SPINE, SecurityLakeSink

ORG_ACCOUNT = "external_synthetic-org"
REGION = "us-east-1"
BATCH = "https://synthetic.okta.example/api/v1/logs?after=synthetic-after-0001"
DAY_ONE_MS = 1_788_566_401_000  # 2026-09-05T00:00:01Z
DAY_TWO_MS = 1_788_652_801_000  # 2026-09-06T00:00:01Z


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_788_566_400.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def event(
    uid: str,
    *,
    time_ms: int = DAY_ONE_MS,
    class_uid: int = 3002,
    **body: Any,
) -> OcsfEvent:
    payload: dict[str, Any] = {
        "class_uid": class_uid,
        "category_uid": 3 if class_uid else 0,
        "activity_id": 1,
        "type_uid": class_uid * 100 + 1,
        "time": time_ms,
        "severity_id": 1,
        "status_id": 1,
        "status": "Success",
        "metadata": {
            "version": "1.3.0",
            "uid": uid,
            "original_time": "2026-09-05T00:00:01.000Z",
            "product": {"name": "Okta System Log", "vendor_name": "Okta"},
            "labels": ["okta-ocsf-mapping:test"],
        },
        "user": {"uid": f"00u{uid}", "name": "Alex Example"},
        "unmapped": {"transaction": {"id": f"synthetic-{uid}"}},
    }
    payload.update(body)
    return OcsfEvent(class_uid=class_uid, time_ms=time_ms, uid=uid, body=payload)


def make_sink(tmp_path: Path, clock: FakeClock | None = None, **overrides: Any) -> SecurityLakeSink:
    return SecurityLakeSink(
        store=LocalObjectStore(tmp_path),
        source_name="okta",
        region=REGION,
        account_id=ORG_ACCOUNT,
        clock=clock or FakeClock(),
        **overrides,
    )


def table_at(sink: SecurityLakeSink, key: str) -> Any:
    store = sink.store
    assert isinstance(store, LocalObjectStore)
    return pq.read_table(BytesIO(store.read(key)))


# --- layout -----------------------------------------------------------------


async def test_the_object_key_is_the_prefix_security_lake_requires(tmp_path: Path) -> None:
    """docs/SPEC.md §4: ext/{source}/region=/accountId=/eventDay=, one custom
    source per OCSF class."""
    sink = make_sink(tmp_path)
    await sink.write([event("a1")])

    await sink.flush(BATCH)

    store = sink.store
    assert isinstance(store, LocalObjectStore)
    (key,) = store.stored_keys()
    prefix, name = key.rsplit("/", 1)
    assert prefix == (
        f"ext/okta_authentication/region={REGION}/accountId={ORG_ACCOUNT}/eventDay=20260905"
    )
    assert name.endswith(".parquet")
    assert len(name) == len("parquet") + 1 + 32, "the cursor is hashed, not embedded"
    assert "okta.example" not in key, "an opaque URL must not leak into a path segment"


async def test_each_class_and_day_becomes_its_own_object(tmp_path: Path) -> None:
    """One OCSF class per object is a vendor requirement; one day per object is
    what the eventDay partition means (§4)."""
    sink = make_sink(tmp_path)
    await sink.write(
        [
            event("a1", class_uid=3002),
            event("b1", class_uid=3001),
            event("c1", class_uid=3002, time_ms=DAY_TWO_MS),
        ]
    )

    await sink.flush(BATCH)

    store = sink.store
    assert isinstance(store, LocalObjectStore)
    assert len(store.stored_keys()) == 3
    sources = {key.split("/")[1] for key in store.stored_keys()}
    assert sources == {"okta_authentication", "okta_account_change"}
    days = {key.split("eventDay=")[1].split("/")[0] for key in store.stored_keys()}
    assert days == {"20260905", "20260906"}


async def test_an_unmapped_event_goes_to_the_base_event_source(tmp_path: Path) -> None:
    sink = make_sink(tmp_path)
    await sink.write([event("a1", class_uid=0, category_uid=0, type_uid=0)])

    await sink.flush(BATCH)

    store = sink.store
    assert isinstance(store, LocalObjectStore)
    assert store.stored_keys()[0].split("/")[1] == "okta_base_event"


# --- what is actually in the object -----------------------------------------


async def test_the_object_is_zstd_parquet_sorted_by_time(tmp_path: Path) -> None:
    sink = make_sink(tmp_path)
    await sink.write(
        [
            event("late", time_ms=DAY_ONE_MS + 5_000),
            event("early", time_ms=DAY_ONE_MS),
            event("middle", time_ms=DAY_ONE_MS + 1_000),
        ]
    )

    await sink.flush(BATCH)

    store = sink.store
    assert isinstance(store, LocalObjectStore)
    (key,) = store.stored_keys()
    raw = store.read(key)
    metadata = pq.ParquetFile(BytesIO(raw)).metadata
    assert metadata.row_group(0).column(0).compression == "ZSTD"
    assert metadata.num_rows == 3

    table = pq.read_table(BytesIO(raw))
    assert table.column("time").to_pylist() == sorted(table.column("time").to_pylist())
    assert [m["uid"] for m in table.column("metadata").to_pylist()] == ["early", "middle", "late"]


async def test_the_declared_spine_is_identical_across_objects(tmp_path: Path) -> None:
    """The Glue table's core must not drift between objects, whatever the class
    or which optional fields an event happened to carry."""
    sink = make_sink(tmp_path)
    await sink.write([event("a1", class_uid=3002), event("b1", class_uid=3004, user=None)])

    await sink.flush(BATCH)

    store = sink.store
    assert isinstance(store, LocalObjectStore)
    for key in store.stored_keys():
        schema = pq.read_schema(BytesIO(store.read(key)))
        for spine_field in SPINE:
            assert schema.field(spine_field.name).type == spine_field.type, spine_field.name


async def test_the_spine_declares_every_metadata_field_the_mapper_emits() -> None:
    """pyarrow drops struct keys the declared type does not name -- silently, no
    error, no warning. So a metadata field added to the mapper and forgotten here
    would vanish between mapping and Parquet, which is precisely the silent
    discarding this connector refuses (§3.3). This is the test that notices."""
    event = OktaOcsfMapper().map(
        {"uuid": "a1", "published": "2026-09-05T00:00:01Z", "eventType": "user.session.start"}
    )

    declared = {field.name for field in SPINE.field("metadata").type}

    assert set(event.body["metadata"]) <= declared, (
        f"mapper emits metadata the spine drops: {set(event.body['metadata']) - declared}"
    )


async def test_the_vendor_event_code_reaches_parquet(tmp_path: Path) -> None:
    sink = make_sink(tmp_path)
    mapper = OktaOcsfMapper()
    await sink.write(
        [
            mapper.map(
                {"uuid": "a1", "published": "2026-09-05T00:00:01Z", "eventType": "nope.not.known"}
            )
        ]
    )

    await sink.flush(BATCH)

    store = sink.store
    assert isinstance(store, LocalObjectStore)
    metadata = table_at(sink, store.stored_keys()[0]).column("metadata").to_pylist()[0]
    assert metadata["event_code"] == "nope.not.known"


async def test_unmapped_travels_as_json(tmp_path: Path) -> None:
    """Its shape is whatever the vendor sent, which no column type describes
    (§3.3). Losing it would be the silent discarding the whole design refuses."""
    sink = make_sink(tmp_path)
    await sink.write([event("a1")])

    await sink.flush(BATCH)

    store = sink.store
    assert isinstance(store, LocalObjectStore)
    table = table_at(sink, store.stored_keys()[0])
    assert json.loads(table.column("unmapped").to_pylist()[0]) == {
        "transaction": {"id": "synthetic-a1"}
    }


async def test_a_column_that_is_null_for_every_row_is_dropped(tmp_path: Path) -> None:
    """An inferred all-null column becomes Arrow's null type, which lands in the
    Glue table as something nothing can query. Better absent than unqueryable."""
    sink = make_sink(tmp_path)
    await sink.write([event("a1", service=None), event("b1", service=None)])

    await sink.flush(BATCH)

    store = sink.store
    assert isinstance(store, LocalObjectStore)
    schema = pq.read_schema(BytesIO(store.read(store.stored_keys()[0])))
    assert "service" not in schema.names
    assert "user" in schema.names, "a column with values is still inferred"


# --- idempotence and cadence ------------------------------------------------


async def test_replaying_a_batch_rewrites_its_object(tmp_path: Path) -> None:
    """The crash in the ack->commit gap replays the batch. It must overwrite,
    not accumulate (docs/SPEC.md §5.2)."""
    sink = make_sink(tmp_path)
    await sink.write([event("a1"), event("b1")])
    await sink.flush(BATCH)

    await sink.write([event("a1"), event("b1")])
    await sink.flush(BATCH)

    store = sink.store
    assert isinstance(store, LocalObjectStore)
    assert len(store.stored_keys()) == 1, "one object, not two"
    assert len(store.written) == 2, "though it was written twice"
    assert table_at(sink, store.stored_keys()[0]).num_rows == 2, "holding one copy of each event"


async def test_a_different_batch_key_is_a_different_object(tmp_path: Path) -> None:
    sink = make_sink(tmp_path)
    await sink.write([event("a1")])
    await sink.flush(BATCH)
    await sink.write([event("b1")])
    await sink.flush(BATCH + "&page=2")

    store = sink.store
    assert isinstance(store, LocalObjectStore)
    assert len(store.stored_keys()) == 2


async def test_flush_with_nothing_buffered_writes_nothing(tmp_path: Path) -> None:
    """The runner flushes at page boundaries; an empty tail page must not
    produce an empty object (§2.2)."""
    sink = make_sink(tmp_path)

    await sink.flush(BATCH)

    store = sink.store
    assert isinstance(store, LocalObjectStore)
    assert store.stored_keys() == []


@pytest.mark.parametrize(
    ("elapsed", "expected"),
    [(0.0, False), (299.0, False), (300.0, True)],
    ids=["just-buffered", "just-under", "at-the-floor"],
)
async def test_should_flush_follows_the_five_minute_cadence(
    tmp_path: Path, elapsed: float, expected: bool
) -> None:
    """§4: objects between 5 minutes and a day, more often only above 256 MB."""
    clock = FakeClock()
    sink = make_sink(tmp_path, clock)
    await sink.write([event("a1")])

    clock.advance(elapsed)

    assert sink.should_flush is expected


async def test_a_full_buffer_flushes_before_the_clock_says_so(tmp_path: Path) -> None:
    """§4: more often than the five-minute floor only when an object would
    otherwise exceed the size ceiling.

    Asserted in both directions, because a threshold test that only checks the
    triggering side passes just as happily when the rule is "always flush".
    """
    clock = FakeClock()
    roomy = make_sink(tmp_path, clock)
    tiny = make_sink(tmp_path, clock, max_bytes=100)

    await roomy.write([event("a1")])
    await tiny.write([event("a1")])

    assert not roomy.should_flush, "cadence has not elapsed and the buffer is small"
    assert tiny.should_flush, "size beats cadence once the buffer is large"


async def test_an_empty_buffer_never_asks_to_flush(tmp_path: Path) -> None:
    clock = FakeClock()
    sink = make_sink(tmp_path, clock)

    clock.advance(10_000)

    assert not sink.should_flush


async def test_flushing_clears_the_buffer(tmp_path: Path) -> None:
    """A batch that flushed twice would double-count its bytes and re-emit its
    events into the next batch's object."""
    clock = FakeClock()
    sink = make_sink(tmp_path, clock)
    await sink.write([event("a1")])
    await sink.flush(BATCH)

    clock.advance(10_000)
    assert not sink.should_flush

    await sink.write([event("b1")])
    await sink.flush(BATCH + "&page=2")

    store = sink.store
    assert isinstance(store, LocalObjectStore)
    second = next(key for key in store.stored_keys() if key != store.written[0])
    uids = [m["uid"] for m in table_at(sink, second).column("metadata").to_pylist()]
    assert uids == ["b1"], "the first batch's events did not ride along"
