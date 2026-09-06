"""Sink seam.

The contract that makes the whole pipeline correct: ``flush`` returns only after
the batch is durable. The runner persists the cursor strictly after that return.
A sink that acknowledges optimistically breaks the delivery guarantee no matter
what the rest of the connector does. See docs/SPEC.md §5.
"""

from __future__ import annotations

from typing import Protocol

from ocsf_connector.mapping.base import OcsfEvent


class Sink(Protocol):
    name: str

    async def write(self, events: list[OcsfEvent]) -> None:
        """Buffer events. May return before anything is durable."""
        ...

    async def flush(self) -> None:
        """Make all buffered events durable. Returns only on success, raises
        otherwise. The runner treats a clean return as the acknowledgement that
        licenses a cursor commit."""
        ...

    @property
    def should_flush(self) -> bool:
        """Whether the buffer has hit its flush trigger.

        For Security Lake this is 5 minutes elapsed or 256 MB buffered,
        whichever comes first -- the vendor's own object cadence guidance, in
        tension with keeping the un-acked replay window short.
        """
        ...
