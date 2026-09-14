"""The object-store seam.

Small, but it carries the property the whole exactly-once story leans on: the
same key written twice leaves one object (docs/SPEC.md §5.2). If that is not
true of the destination, nothing the sink or runner does can make delivery
effectively-once.
"""

from __future__ import annotations

from pathlib import Path

from ocsf_connector.sinks.objects import LocalObjectStore

KEY = (
    "ext/okta_authentication/region=us-east-1"
    "/accountId=external_synthetic/eventDay=20260905/abc.parquet"
)


async def test_a_key_becomes_the_path_it_describes(tmp_path: Path) -> None:
    """The Security Lake prefix should be legible on disk, so a layout mistake
    is visible without deploying anything (§4)."""
    store = LocalObjectStore(tmp_path)

    await store.put(KEY, b"parquet-bytes")

    assert (tmp_path / KEY).read_bytes() == b"parquet-bytes"
    assert store.stored_keys() == [KEY]


async def test_writing_the_same_key_twice_leaves_one_object(tmp_path: Path) -> None:
    """A replayed batch re-derives its key and overwrites. Two objects here
    would mean duplicate events in the lake (§5.2)."""
    store = LocalObjectStore(tmp_path)

    await store.put(KEY, b"first")
    await store.put(KEY, b"replayed")

    assert store.stored_keys() == [KEY], "one object"
    assert store.read(KEY) == b"replayed", "holding the later write"
    assert store.written == [KEY, KEY], "though both writes happened"


async def test_objects_under_different_partitions_coexist(tmp_path: Path) -> None:
    store = LocalObjectStore(tmp_path)
    other = KEY.replace("eventDay=20260905", "eventDay=20260906")

    await store.put(KEY, b"day one")
    await store.put(other, b"day two")

    assert store.stored_keys() == sorted([KEY, other])
