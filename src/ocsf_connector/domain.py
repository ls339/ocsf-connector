"""The two types that cross seams.

``Cursor`` and ``OcsfEvent`` are what flows through the pipeline: a position and
a payload. Every package touches at least one of them, which is why they live
here rather than inside whichever package happened to define them first.

They used to. ``Cursor`` sat in ``sources.base`` and ``OcsfEvent`` in
``mapping.base``, which made ``state`` import from ``sources`` and ``sinks``
import from ``mapping`` -- type-only edges, but ones that said something untrue
about the design. The state store does not fetch anything and the sink does not
map anything; neither should need the package that does.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

Cursor = str
"""The URL to GET next.

Persisted verbatim and never parsed. Only the *opening* cursor is built by a
source, and only from configured query parameters; every later one comes from
the vendor's ``Link`` header. The ``after`` value inside is never constructed or
read. See docs/SPEC.md §2.2.
"""


@dataclass(frozen=True, slots=True)
class OcsfEvent:
    """A mapped event, ready for a sink.

    ``class_uid`` is lifted out of ``body`` because Security Lake requires one
    OCSF class per Parquet object, so the sink must bucket on it without
    inspecting the payload. ``time_ms`` is lifted for the same reason: objects
    partition by ``eventDay`` and records within an object sort by time.
    """

    class_uid: int
    time_ms: int
    uid: str
    """Source event id -- Okta's ``uuid``. The dedup key. See docs/SPEC.md §5."""
    body: dict[str, Any]
