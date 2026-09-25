"""Where a finished object goes.

The Security Lake sink's correctness argument (docs/SPEC.md §5.2) rests on one
property of the destination: **writing the same key twice leaves one object,
holding the second write**. S3 PUT is exactly that, and so is writing a file. So
the seam is one method, and the sink can be tested end to end -- layout, naming,
Parquet bytes -- without an AWS account or a network.

It is deliberately not a general object-store abstraction. There is no get, no
list, no delete, because the sink needs none of them and a seam that promises
more than its caller uses is a seam nobody can reimplement confidently.

**A write names its custom source, and the key is relative to that source.**
That split is not decoration. Security Lake assigns each custom source its own
prefix and creates a role per source to write it —
``AmazonSecurityLake-Provider-{source}-{region}``, trusted to a principal and
external id given at registration (§4.2) — so for S3 the credential *and* the
destination both depend on which source an object belongs to, while the
partition layout inside it does not. The sink knows the source, because it knows
the class; the store knows where that source lives, because that is what
registration told it. Passing the whole path instead would leave the store to
recover the source by parsing a key the sink had just built out of it, and a
disagreement between the two would write objects no table points at.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


class ObjectStore(Protocol):
    async def put(self, source: str, key: str, data: bytes) -> None:
        """Write ``data`` for custom source ``source``, at ``key`` within it.

        ``source`` is a registered Security Lake custom source, e.g.
        ``okta_authentication``. ``key`` is everything below that source's own
        prefix -- the partition path and object name -- and never repeats the
        source.

        MUST be idempotent on ``(source, key)``: a replayed batch re-derives both
        and must leave one object, not two (docs/SPEC.md §5.2). MUST return only
        once the object is durable -- the sink's ``flush`` returning is what
        licenses the runner to commit its cursor (§5).

        MAY raise for a source it has no destination for. That is a wiring
        mistake rather than a runtime failure -- a newly mapped OCSF class with
        no registered custom source -- and raising keeps the cursor where it is,
        which is the behaviour that lets the run be retried once the source
        exists.
        """
        ...


@dataclass(slots=True)
class LocalObjectStore:
    """Files under ``root``, for tests and for looking at real output by hand.

    Key segments become directories, so the Security Lake prefix appears on disk
    exactly as it would in the bucket -- which is the point: partition layout
    bugs are visible in a directory tree without deploying anything.
    """

    root: Path
    written: list[str] = field(default_factory=list)
    """Paths in the order they were written. A replayed write appears twice here
    while leaving one file, which is what makes idempotency observable."""

    async def put(self, source: str, key: str, data: bytes) -> None:
        # ext/{source}/ is the prefix Security Lake documents for a custom
        # source (§4), reproduced rather than configured: this store exists so
        # that a layout mistake is visible in a directory tree, and it cannot do
        # that while inventing its own arrangement. The S3 store does not derive
        # this -- it is told each source's location by registration (§4.2).
        path = self.root / self.path_for(source, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        # write_bytes truncates, so a rewrite replaces rather than appends --
        # the same semantics the sink relies on from S3.
        path.write_bytes(data)
        self.written.append(self.path_for(source, key))

    @staticmethod
    def path_for(source: str, key: str) -> str:
        """Where a write lands, as the bucket would show it."""
        return f"ext/{source}/{key}"

    def stored_keys(self) -> list[str]:
        """Every object currently stored, as the bucket would show it.

        Inspection, not the seam: these are full paths including the
        ``ext/{source}/`` prefix, which is what an operator looking in the bucket
        sees and what :meth:`read` takes. Deliberately a different vocabulary
        from :meth:`put`, whose job is to *decide* where an object goes.

        Not ``keys()``: this is not a mapping, and a method by that name reads
        like one to people and to linters alike.
        """
        return sorted(
            str(path.relative_to(self.root)) for path in self.root.rglob("*") if path.is_file()
        )

    def read(self, key: str) -> bytes:
        return (self.root / key).read_bytes()
