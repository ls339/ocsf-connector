"""Mapping seam: vendor event -> OCSF event.

Parameterized by target OCSF version because the sink, not the spec, sets the
ceiling: OCSF is at 1.9.0 but Amazon Security Lake accepts 1.3 and earlier from
custom sources. See docs/SPEC.md §3.1.

The mapping itself is data (``okta_ocsf.yaml``), not control flow. An unknown
vendor event type is a normal, expected condition -- it degrades to a generic
class with the source event preserved under ``unmapped`` and bumps a counter.
It must never raise and must never silently drop.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


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


class Mapper(Protocol):
    ocsf_version: str
    mapping_version: str
    """Revision of the mapping table. Recorded alongside every write so any
    record can be traced back to the rules that produced it."""

    def map(self, record: dict[str, Any]) -> OcsfEvent:
        """Normalize one vendor record. Total function -- never raises."""
        ...
