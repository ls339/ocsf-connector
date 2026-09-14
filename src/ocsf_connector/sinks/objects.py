"""Where a finished object goes.

The Security Lake sink's correctness argument (docs/SPEC.md §5.2) rests on one
property of the destination: **writing the same key twice leaves one object,
holding the second write**. S3 PUT is exactly that, and so is writing a file. So
the seam is one method, and the sink can be tested end to end -- layout, naming,
Parquet bytes -- without an AWS account or a network.

It is deliberately not a general object-store abstraction. There is no get, no
list, no delete, because the sink needs none of them and a seam that promises
more than its caller uses is a seam nobody can reimplement confidently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


class ObjectStore(Protocol):
    async def put(self, key: str, data: bytes) -> None:
        """Write ``data`` at ``key``, replacing whatever was there.

        MUST be idempotent on ``key``: a replayed batch re-derives the same key
        and must leave one object, not two (docs/SPEC.md §5.2). MUST return only
        once the object is durable -- the sink's ``flush`` returning is what
        licenses the runner to commit its cursor (§5).
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
    """Keys in the order they were written. A replayed key appears twice here
    while leaving one file, which is what makes idempotency observable."""

    async def put(self, key: str, data: bytes) -> None:
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        # write_bytes truncates, so a rewrite replaces rather than appends --
        # the same semantics the sink relies on from S3.
        path.write_bytes(data)
        self.written.append(key)

    def stored_keys(self) -> list[str]:
        """Every object currently stored, as keys rather than paths.

        Not ``keys()``: this is not a mapping, and a method by that name reads
        like one to people and to linters alike.
        """
        return sorted(
            str(path.relative_to(self.root)) for path in self.root.rglob("*") if path.is_file()
        )

    def read(self, key: str) -> bytes:
        return (self.root / key).read_bytes()
