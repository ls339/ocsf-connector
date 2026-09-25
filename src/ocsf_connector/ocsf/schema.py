"""OCSF 1.3.0 as data, read once at import.

Two modules need to know what an OCSF class is, for different reasons. The
mapper decides which attributes a record may carry and which activity ids are
legal; the sink decides which Security Lake custom source a class is written to.
Both used to hold their own copy in Python, with nothing relating them: adding a
class meant editing two files that no compiler, and no test, connected.

The sink's *names* moved back out, to `sinks/naming.py`, once AWS's 20-character
cap on a custom source name made three of the OCSF class names unusable. What
stays related is the obligation: every class defined here has exactly one source
name there, and a test holds the two together (§4.1).

This package is deliberately neutral. Putting the schema under ``mapping/``
would have recreated the ``sinks -> mapping`` edge that was just removed -- the
sink does not map anything, and should not import from something that does.

What stays out of here: ``STATUS_IDS`` and ``SEVERITY_IDS`` in the Okta mapper
translate *Okta's* vocabulary into OCSF ids. That is vendor mapping, not OCSF
schema, and it belongs beside the vendor it describes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

SCHEMA_PATH = Path(__file__).with_name("v1_3_0.yaml")


def _document() -> dict[str, Any]:
    loaded = yaml.safe_load(SCHEMA_PATH.read_text())
    return loaded if isinstance(loaded, dict) else {}


_SCHEMA = _document()
_CLASSES: dict[int, dict[str, Any]] = {
    int(uid): definition for uid, definition in (_SCHEMA.get("classes") or {}).items()
}

VERSION: str = str(_SCHEMA.get("version", "1.3.0"))
"""The emitted schema version, recorded in ``metadata.version`` on every event."""

BASE_ATTRIBUTES: frozenset[str] = frozenset(_SCHEMA.get("base_attributes") or ())
"""Attributes every class carries, whatever it is."""

CLASS_CATEGORY_UID: dict[int, int] = {
    uid: int(definition["category_uid"]) for uid, definition in _CLASSES.items()
}

ACTIVITY_IDS: dict[int, frozenset[int]] = {
    uid: frozenset(int(activity) for activity in definition.get("activities") or ())
    for uid, definition in _CLASSES.items()
}
"""Legal ``activity_id`` values per class. A mapping table naming anything else
is refused at load time rather than emitting records the target version rejects."""

CLASS_ATTRIBUTES: dict[int, frozenset[str]] = {
    uid: frozenset(definition.get("attributes") or ()) for uid, definition in _CLASSES.items()
}
"""What each class defines *beyond* the base event. An attribute a class does not
define makes the record invalid for that class, so every event is filtered."""

REQUIRED_OBJECTS: dict[int, tuple[str, ...]] = {
    uid: tuple(definition.get("required") or ()) for uid, definition in _CLASSES.items()
}
"""The objects a class requires. Filled with a thin placeholder when absent: an
invalid record helps nobody downstream."""

CLASS_NAMES: dict[int, str] = {uid: str(definition["name"]) for uid, definition in _CLASSES.items()}
"""OCSF 1.3.0's own name for each class.

Not the Security Lake custom source name, which it used to be. AWS caps that at
20 characters and three of these do not fit, so the source names are an
AWS-shaped table in `sinks/naming.py` -- keeping OCSF's names here honest about
the version they describe (§4.1)."""
