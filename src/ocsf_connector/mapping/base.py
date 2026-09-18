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

from typing import Any, Protocol

from ocsf_connector.domain import OcsfEvent

__all__ = ["Mapper", "OcsfEvent"]


class Mapper(Protocol):
    ocsf_version: str
    mapping_version: str
    """Revision of the mapping table. Recorded alongside every write so any
    record can be traced back to the rules that produced it."""

    def map(self, record: dict[str, Any]) -> OcsfEvent:
        """Normalize one vendor record. Total function -- never raises."""
        ...
