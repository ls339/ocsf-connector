"""Shared fixtures.

The important one is ``stores``: a state store suite runs against *both*
implementations, because the in-memory store and the durable one make the same
promises for different reasons. In-memory atomicity is free -- its state is an
object, and an object either exists or does not. Durable atomicity is a claim
about a file, a transaction, and an fsync, and the only way to believe it is to
close the handle and open the file again.

That is what ``reopen`` means, and why it differs per implementation: for the
in-memory store the state *is* the object, so a restart returns the same object;
for SQLite it drops the connection and reconnects to the same path, which is a
genuine restart against genuinely durable state.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from ocsf_connector.state.memory import InMemoryStateStore
from ocsf_connector.state.sqlite import SqliteStateStore
from ocsf_connector.state.store import StateStore


class StoreHarness:
    """One store, plus the ability to reopen the same state as a fresh handle."""

    def __init__(self, kind: str, path: Path) -> None:
        self.kind = kind
        self.path = path
        self._store: StateStore | None = None
        self._kwargs: dict[str, Any] = {}

    @property
    def durable(self) -> bool:
        return self.kind == "sqlite"

    def open(self, **kwargs: Any) -> StateStore:
        if self._store is None:
            self._kwargs = kwargs
            self._store = self._construct()
        return self._store

    def reopen(self) -> StateStore:
        """The same state, a fresh handle -- what a process restart looks like."""
        if self._store is None:
            return self.open()
        if not self.durable:
            # Its state is the object; handing back a new one would be amnesia,
            # not a restart.
            return self._store
        self.close()
        self._store = self._construct()
        return self._store

    def close(self) -> None:
        store = self._store
        if store is not None and isinstance(store, SqliteStateStore):
            store.close()
        self._store = None

    def _construct(self) -> StateStore:
        if self.durable:
            return SqliteStateStore(self.path, **self._kwargs)
        return InMemoryStateStore(**self._kwargs)


@pytest.fixture(params=["memory", "sqlite"])
def stores(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[StoreHarness]:
    harness = StoreHarness(kind=request.param, path=tmp_path / "state.db")
    yield harness
    harness.close()
