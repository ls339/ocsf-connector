"""The object-store seam.

Small, but it carries the property the whole exactly-once story leans on: the
same write twice leaves one object (docs/SPEC.md §5.2). If that is not true of
the destination, nothing the sink or runner does can make delivery
effectively-once.

A write names its custom source separately from the key, because Security Lake
gives each source its own prefix and its own write role (§4.2). That makes the
source the only thing separating two objects that are otherwise identical --
same batch, same day, different class -- so it is tested as such below.
"""

from __future__ import annotations

from pathlib import Path

from ocsf_connector.sinks.objects import LocalObjectStore

SOURCE = "okta_authentication"
PARTITION = "region=us-east-1/accountId=external_synthetic/eventDay=20260905/abc.parquet"
KEY = f"ext/{SOURCE}/{PARTITION}"


async def test_a_write_lands_where_the_bucket_would_show_it(tmp_path: Path) -> None:
    """The Security Lake prefix should be legible on disk, so a layout mistake
    is visible without deploying anything (§4)."""
    store = LocalObjectStore(tmp_path)

    await store.put(SOURCE, PARTITION, b"parquet-bytes")

    assert (tmp_path / KEY).read_bytes() == b"parquet-bytes"
    assert store.stored_keys() == [KEY]


async def test_writing_the_same_place_twice_leaves_one_object(tmp_path: Path) -> None:
    """A replayed batch re-derives its source and key and overwrites. Two objects
    here would mean duplicate events in the lake (§5.2)."""
    store = LocalObjectStore(tmp_path)

    await store.put(SOURCE, PARTITION, b"first")
    await store.put(SOURCE, PARTITION, b"replayed")

    assert store.stored_keys() == [KEY], "one object"
    assert store.read(KEY) == b"replayed", "holding the later write"
    assert store.written == [KEY, KEY], "though both writes happened"


async def test_objects_under_different_partitions_coexist(tmp_path: Path) -> None:
    store = LocalObjectStore(tmp_path)
    other = PARTITION.replace("eventDay=20260905", "eventDay=20260906")

    await store.put(SOURCE, PARTITION, b"day one")
    await store.put(SOURCE, other, b"day two")

    assert store.stored_keys() == sorted([KEY, f"ext/{SOURCE}/{other}"])


async def test_two_sources_sharing_a_key_do_not_collide(tmp_path: Path) -> None:
    """The failure this seam's shape could introduce, so it is asserted directly.

    Two classes flushed from one batch derive the *same* key: the digest is the
    batch's opening cursor and the day is the day. Only the source separates
    them, so a store that accepted the source and then ignored it would leave one
    object holding whichever class was written last -- half the batch gone, with
    the cursor committed and nothing raised.
    """
    store = LocalObjectStore(tmp_path)

    await store.put("okta_authentication", PARTITION, b"authentication")
    await store.put("okta_account_change", PARTITION, b"account change")

    assert store.stored_keys() == sorted(
        [f"ext/okta_authentication/{PARTITION}", f"ext/okta_account_change/{PARTITION}"]
    ), "two objects, one per source"
    assert store.read(f"ext/okta_authentication/{PARTITION}") == b"authentication"
    assert store.read(f"ext/okta_account_change/{PARTITION}") == b"account change"


async def test_the_key_a_caller_passes_never_repeats_the_source(tmp_path: Path) -> None:
    """Belt and braces on the division of labour. A caller that kept building
    the whole path would still "work" -- the file would land somewhere -- and the
    S3 store would then be handed a key that walks outside the prefix its role
    can write."""
    store = LocalObjectStore(tmp_path)

    await store.put(SOURCE, PARTITION, b"bytes")

    (stored,) = store.stored_keys()
    assert stored.count(SOURCE) == 1, f"the source appears twice in {stored}"
    assert stored.startswith(f"ext/{SOURCE}/region=")
