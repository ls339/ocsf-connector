"""State store behavior: TTL, ordering, atomicity, and durability.

Every test here runs against both implementations (see ``conftest.StoreHarness``),
because the protocol is what the runner depends on and an implementation that
only nearly satisfies it is the kind of thing that shows up as lost events much
later. The last few tests are durability-only: they assert the properties an
in-memory store cannot have.
"""

from __future__ import annotations

import asyncio

import pytest

from ocsf_connector.state.sqlite import SqliteStateStore
from tests.conftest import StoreHarness

STREAM = "okta-system-log"
MAPPING = "okta-2026.09.01"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_788_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


async def test_filter_unseen_preserves_order_and_collapses_repeats(
    stores: StoreHarness,
) -> None:
    store = stores.open()

    assert await store.filter_unseen(["a1", "b1", "a1", "c1"]) == ["a1", "b1", "c1"]


async def test_filter_unseen_handles_an_empty_batch(stores: StoreHarness) -> None:
    assert await stores.open().filter_unseen([]) == []


async def test_committed_uids_are_filtered_until_the_ttl_expires(
    stores: StoreHarness,
) -> None:
    clock = FakeClock()
    store = stores.open(ttl_seconds=100, clock=clock)
    await store.commit(STREAM, "c1", ["a1"], MAPPING)

    assert await store.filter_unseen(["a1", "b1"]) == ["b1"]

    clock.advance(101)
    assert await store.filter_unseen(["a1", "b1"]) == ["a1", "b1"]


async def test_purge_expired_drops_only_expired_uids(stores: StoreHarness) -> None:
    clock = FakeClock()
    store = stores.open(ttl_seconds=100, clock=clock)
    await store.commit(STREAM, "c1", ["a1"], MAPPING)
    clock.advance(60)
    await store.commit(STREAM, "c2", ["b1"], MAPPING)

    clock.advance(50)  # a1 expired at +100, b1 expires at +160
    assert await store.purge_expired() == 1
    assert await store.filter_unseen(["a1", "b1"]) == ["a1"]


async def test_last_published_only_moves_forward_and_is_not_the_cursor(
    stores: StoreHarness,
) -> None:
    store = stores.open()
    await store.record_published(STREAM, 2_000)
    await store.record_published(STREAM, 1_000)

    assert await store.get_cursor(STREAM) is None, "published must never become resume state"
    if isinstance(store, SqliteStateStore):
        assert await store.get_last_published(STREAM) == 2_000, "and it never goes backwards"


async def test_a_finished_range_is_distinguishable_from_a_fresh_stream(
    stores: StoreHarness,
) -> None:
    """A bounded range that completes commits a ``None`` cursor. So does nothing
    at all, and the two must not look alike (docs/SPEC.md §5.3)."""
    store = stores.open()
    assert not store.has_committed(STREAM)

    await store.commit(STREAM, None, ["a1"], MAPPING)

    assert await store.get_cursor(STREAM) is None
    assert store.has_committed(STREAM)


async def test_commit_advances_the_cursor_and_the_mapping_version_together(
    stores: StoreHarness,
) -> None:
    store = stores.open()
    await store.commit(STREAM, "c1", ["a1"], MAPPING)
    await store.commit(STREAM, "c2", ["b1"], "okta-2026.09.04")

    assert await store.get_cursor(STREAM) == "c2"
    assert await store.get_mapping_version(STREAM) == "okta-2026.09.04"


async def test_streams_do_not_share_a_cursor(stores: StoreHarness) -> None:
    store = stores.open()
    await store.commit("okta", "c1", [], MAPPING)
    await store.commit("tailscale", "t1", [], MAPPING)

    assert await store.get_cursor("okta") == "c1"
    assert await store.get_cursor("tailscale") == "t1"


# --- durability: what an in-memory store cannot show ------------------------


async def test_a_commit_survives_reopening_the_file(stores: StoreHarness) -> None:
    """The point of the durable store. Everything above is true of a dict."""
    if not stores.durable:
        pytest.skip("in-memory state does not outlive the handle")

    store = stores.open()
    await store.commit(STREAM, "c1", ["a1"], MAPPING)

    restarted = stores.reopen()

    assert await restarted.get_cursor(STREAM) == "c1"
    assert await restarted.get_mapping_version(STREAM) == MAPPING
    assert restarted.has_committed(STREAM), "recovered from the file, not from memory"
    assert await restarted.filter_unseen(["a1", "b1"]) == ["b1"], "the seen-set survived too"


async def test_a_finished_range_still_reads_as_finished_after_a_restart(
    stores: StoreHarness,
) -> None:
    if not stores.durable:
        pytest.skip("in-memory state does not outlive the handle")

    store = stores.open()
    await store.commit(STREAM, None, ["a1"], MAPPING)

    restarted = stores.reopen()

    assert await restarted.get_cursor(STREAM) is None
    assert restarted.has_committed(STREAM), "a completed range must not look like a fresh stream"


async def test_a_transaction_killed_mid_flight_leaves_nothing_behind(
    stores: StoreHarness,
) -> None:
    """docs/SPEC.md §5.1: a crash during commit leaves *neither* the cursor nor
    the seen-set. Here the crash is real -- the connection closes with a
    transaction still open -- and the file is asked afterwards."""
    if not stores.durable:
        pytest.skip("only a real transaction can be interrupted")

    store = stores.open()
    await store.commit(STREAM, "c1", ["a1"], MAPPING)

    dying = SqliteStateStore(stores.path)
    dying._conn.execute("BEGIN IMMEDIATE")
    dying._conn.execute(
        "UPDATE streams SET cursor = 'c2' WHERE stream = ?",
        (STREAM,),
    )
    dying._conn.execute("INSERT OR REPLACE INTO seen (uid, expires_at) VALUES ('b1', 1e12)")
    dying.close()  # no COMMIT: the process died in the ack->commit gap

    restarted = stores.reopen()

    assert await restarted.get_cursor(STREAM) == "c1", "the half-written cursor did not land"
    assert await restarted.filter_unseen(["b1"]) == ["b1"], "and neither did its seen-set"


async def test_commit_is_exactly_one_transaction(stores: StoreHarness) -> None:
    """docs/SPEC.md §5.1: the cursor and the seen-set advance in one commit,
    because two would open a third crash window between them.

    No black-box assertion can tell one transaction from two -- both leave the
    same rows behind when nothing goes wrong -- so this watches the SQL itself.
    """
    if not stores.durable:
        pytest.skip("only the durable store has transactions to count")

    store = stores.open()
    assert isinstance(store, SqliteStateStore)
    traced: list[str] = []
    store._conn.set_trace_callback(lambda sql: traced.append(" ".join(sql.split())[:32]))
    try:
        await store.commit(STREAM, "c1", ["a1", "a2"], MAPPING)
    finally:
        store._conn.set_trace_callback(None)

    assert sum(sql.startswith("BEGIN") for sql in traced) == 1, traced
    assert sum(sql.startswith("COMMIT") for sql in traced) == 1, traced
    assert traced[0].startswith("BEGIN"), traced
    assert traced[-1].startswith("COMMIT"), traced
    written = [sql for sql in traced if "INSERT" in sql]
    assert written, "the writes happen inside that transaction, not around it"


async def test_the_durable_ttl_is_stamped_on_the_wall_clock(stores: StoreHarness) -> None:
    """A TTL that outlives the process cannot be measured by a clock that
    restarts with it.

    ``time.monotonic`` counts from an arbitrary origin -- commonly boot -- so an
    expiry stamped with one reads as far in the future after a restart, and the
    seen-set never expires. The stored value has to be epoch-scale, and nothing
    else about the store's behavior reveals which clock wrote it.
    """
    if not stores.durable:
        pytest.skip("an in-memory TTL dies with the process, so monotonic is fine there")

    store = stores.open()
    assert isinstance(store, SqliteStateStore)
    await store.commit(STREAM, "c1", ["a1"], MAPPING)

    row = store._conn.execute("SELECT expires_at FROM seen WHERE uid = 'a1'").fetchone()

    assert row[0] > 1_700_000_000, "expiry was stamped from a monotonic clock, not epoch time"


async def test_concurrent_commits_do_not_collide(stores: StoreHarness) -> None:
    """A SQLite connection may be shared across threads but holds one
    transaction at a time: overlapping ``BEGIN IMMEDIATE`` calls raise "cannot
    start a transaction within a transaction". The store serializes them, and
    this is the test that fails when that serialization is removed."""
    store = stores.open()

    await asyncio.gather(
        *(
            store.commit(f"stream-{index}", f"c{index}", [f"u{index}"], MAPPING)
            for index in range(8)
        )
    )

    for index in range(8):
        assert await store.get_cursor(f"stream-{index}") == f"c{index}"
    assert await store.filter_unseen([f"u{index}" for index in range(8)]) == []
