"""Sink seam.

The contract that makes the whole pipeline correct: ``flush`` returns only after
the batch is durable. The runner persists the cursor strictly after that return.
A sink that acknowledges optimistically breaks the delivery guarantee no matter
what the rest of the connector does. See docs/SPEC.md §5.

``flush`` takes a ``batch_key``, and that argument is load-bearing. A crash
between the sink ack and the cursor commit replays the batch; the seen-set does
not absorb that replay, because an atomic commit means the seen-set was lost in
the same crash. Exactly-once at the sink therefore rests on the *write* being
idempotent: the batch is addressed by the cursor it started from, which is
stable across replay, so a replayed batch overwrites its object instead of
adding a second one. See docs/SPEC.md §5.2.
"""

from __future__ import annotations

from typing import Protocol

from ocsf_connector.mapping.base import OcsfEvent


class Sink(Protocol):
    name: str

    async def write(self, events: list[OcsfEvent]) -> None:
        """Buffer events. May return before anything is durable."""
        ...

    async def flush(self, batch_key: str) -> None:
        """Make all buffered events durable, addressed by ``batch_key``.

        Returns only on success, raises otherwise. The runner treats a clean
        return as the acknowledgement that licenses a cursor commit.

        Writing the same ``batch_key`` twice MUST leave one batch, not two --
        for the Security Lake sink, by deriving the object key from it and
        letting the PUT overwrite. ``batch_key`` is the opaque cursor the batch
        began at, so it is not safe to use as a path segment unescaped.
        """
        ...

    @property
    def should_flush(self) -> bool:
        """Whether the buffer has hit its flush trigger.

        For Security Lake this is 5 minutes elapsed or 256 MB buffered,
        whichever comes first -- the vendor's own object cadence guidance, in
        tension with keeping the un-acked replay window short. Read only at page
        boundaries, so a batch is always a whole number of source pages.
        """
        ...
