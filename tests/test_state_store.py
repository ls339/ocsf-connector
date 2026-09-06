"""The in-memory store's own behavior: TTL, ordering, and atomicity."""

from __future__ import annotations

from ocsf_connector.state.memory import InMemoryStateStore


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


async def test_filter_unseen_preserves_order_and_collapses_repeats() -> None:
    store = InMemoryStateStore()
    assert await store.filter_unseen(["a1", "b1", "a1", "c1"]) == ["a1", "b1", "c1"]


async def test_committed_uids_are_filtered_until_the_ttl_expires() -> None:
    clock = FakeClock()
    store = InMemoryStateStore(ttl_seconds=100, clock=clock)
    await store.commit("s", "c1", ["a1"], "okta-2026.09.01")

    assert await store.filter_unseen(["a1", "b1"]) == ["b1"]

    clock.advance(101)
    assert await store.filter_unseen(["a1", "b1"]) == ["a1", "b1"]


async def test_purge_expired_drops_only_expired_uids() -> None:
    clock = FakeClock()
    store = InMemoryStateStore(ttl_seconds=100, clock=clock)
    await store.commit("s", "c1", ["a1"], "okta-2026.09.01")
    clock.advance(60)
    await store.commit("s", "c2", ["b1"], "okta-2026.09.01")

    clock.advance(50)  # a1 expired at 100, b1 expires at 160
    assert store.purge_expired() == 1
    assert await store.filter_unseen(["a1", "b1"]) == ["a1"]


async def test_last_published_only_moves_forward_and_is_not_the_cursor() -> None:
    store = InMemoryStateStore()
    await store.record_published("s", 2_000)
    await store.record_published("s", 1_000)

    assert await store.get_cursor("s") is None, "published must never become resume state"


async def test_a_finished_range_is_distinguishable_from_a_fresh_stream() -> None:
    store = InMemoryStateStore()
    assert not store.has_committed("s")

    await store.commit("s", None, ["a1"], "okta-2026.09.01")
    assert await store.get_cursor("s") is None
    assert store.has_committed("s")
