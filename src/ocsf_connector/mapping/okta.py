"""Okta System Log record -> OCSF event.

The table is data (``okta_ocsf.yaml``); this module is the machinery around it
(docs/SPEC.md §3.3). Two rules shape everything here:

**It never raises and never drops.** An unknown ``eventType``, a missing field, a
timestamp Okta phrased differently -- each degrades to something honest rather
than an exception. A mapper that can raise turns a schema change at the vendor
into an outage here, and the runner maps *before* dedup precisely so replays keep
the drift counter alive (§5.1).

**It emits only attributes the target class defines.** OCSF 1.3.0 -- the version
Security Lake accepts (§3.1) -- gives each IAM class a different shape: only
Authentication has ``service``/``session``/``is_mfa``, Entity Management has
``entity`` and no ``user``, and so on. Emitting a stray attribute would produce a
record that fails validation for that class, so the per-class sets below are
checked, not assumed.

Everything the mapping does not consume is preserved under ``unmapped``. That is
a feature: silently discarding source fields is the signature of a toy connector.
"""

from __future__ import annotations

import copy
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from ocsf_connector.mapping.base import OcsfEvent

TABLE_PATH = Path(__file__).with_name("okta_ocsf.yaml")

BASE_EVENT_CLASS_UID = 0

CLASS_CATEGORY_UID = {0: 0, 3001: 3, 3002: 3, 3003: 3, 3004: 3, 3005: 3, 3006: 3}
"""OCSF 1.3.0: Base Event sits in category 0, the six IAM classes in category 3."""

ACTIVITY_IDS: dict[int, frozenset[int]] = {
    0: frozenset({0, 99}),
    3001: frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 99}),
    3002: frozenset({0, 1, 2, 3, 4, 5, 6, 99}),
    3003: frozenset({0, 1, 2, 99}),
    3004: frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 99}),
    3005: frozenset({0, 1, 2, 99}),
    3006: frozenset({0, 1, 2, 3, 4, 5, 6, 99}),
}
"""Verified against the 1.3.0 schema, which is not the current one: Authentication
has no Account Switch (7) until later versions, and IAM has no 3007/3008 here."""

CLASS_ATTRIBUTES: dict[int, frozenset[str]] = {
    0: frozenset(),
    3001: frozenset({"user", "actor", "src_endpoint", "http_request"}),
    3002: frozenset(
        {"user", "actor", "src_endpoint", "http_request", "service", "session", "is_mfa"}
    ),
    3003: frozenset(
        {"user", "actor", "src_endpoint", "http_request", "session", "privileges", "group"}
    ),
    3004: frozenset({"entity", "actor", "src_endpoint", "http_request"}),
    3005: frozenset({"user", "actor", "src_endpoint", "http_request", "privileges"}),
    3006: frozenset({"group", "user", "actor", "src_endpoint", "http_request", "privileges"}),
}
"""What each class defines beyond the base event, profiles excluded. ``cloud`` and
``osint`` read as required in the schema browser but belong to opt-in profiles,
so they are deliberately absent."""

BASE_ATTRIBUTES = frozenset(
    {
        "activity_id",
        "category_uid",
        "class_uid",
        "message",
        "metadata",
        "severity_id",
        "status",
        "status_detail",
        "status_id",
        "time",
        "type_uid",
        "unmapped",
    }
)

REQUIRED_OBJECTS: dict[int, tuple[str, ...]] = {
    0: (),
    3001: ("user",),
    3002: ("user",),
    3003: ("user",),
    3004: ("entity",),
    3005: ("user", "privileges"),
    3006: ("group",),
}

STATUS_IDS = {"SUCCESS": 1, "FAILURE": 2}
"""Okta's documented outcomes. Anything else becomes 99 (Other) rather than being
guessed at, and a missing outcome stays 0 (Unknown)."""

SEVERITY_IDS = {"DEBUG": 1, "INFO": 1, "WARN": 3, "ERROR": 4, "FATAL": 6}


@dataclass(slots=True)
class OktaOcsfMapper:
    """Implements :class:`~ocsf_connector.mapping.base.Mapper` for Okta.

    ``service_name`` satisfies Authentication's ``at_least_one: [service,
    dst_endpoint]`` constraint when an event names no application target -- an
    Okta sign-in is to the org itself, and the constraint has to be met somehow.
    """

    service_name: str = "Okta"
    table_path: Path = TABLE_PATH
    on_unmapped: Callable[[str], None] | None = None
    ocsf_version: str = field(init=False, default="")
    mapping_version: str = field(init=False, default="")
    unmapped_event_types: Counter[str] = field(init=False, default_factory=Counter)
    """Counts by event type, the signal SPEC §7 exports as
    ``unmapped_event_type_total``. Kept here so the alarm works before telemetry
    exists, and so a test can see it."""
    _events: dict[str, dict[str, int]] = field(init=False, default_factory=dict)
    _fallback: dict[str, int] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        loaded = yaml.safe_load(self.table_path.read_text())
        table: dict[str, Any] = loaded if isinstance(loaded, dict) else {}
        self.ocsf_version = str(table.get("ocsf_version", "1.3.0"))
        self.mapping_version = str(table.get("version", "unknown"))
        self._fallback = _entry(table.get("fallback") or {}, "fallback")
        self._events = {
            str(name): _entry(value, name) for name, value in (table.get("events") or {}).items()
        }

    def map(self, record: dict[str, Any]) -> OcsfEvent:
        """Normalize one Okta record. Total: every path returns an event."""
        source = record if isinstance(record, dict) else {}
        event_type = str(source.get("eventType") or "")

        entry = self._events.get(event_type)
        if entry is None:
            # The drift alarm. Counted before the fallback so a new vendor event
            # type is loud the first time and every time (§3.3).
            self.unmapped_event_types[event_type] += 1
            if self.on_unmapped is not None:
                self.on_unmapped(event_type)
            entry = self._fallback

        class_uid = entry["class_uid"]
        activity_id = entry["activity_id"]
        reader = _Reader(source)
        body = self._body(reader, class_uid, activity_id)
        body["unmapped"] = _leftovers(source, reader.consumed)

        return OcsfEvent(
            class_uid=class_uid,
            time_ms=int(body["time"]),
            uid=str(body["metadata"].get("uid", "")),
            body=body,
        )

    def _body(self, reader: _Reader, class_uid: int, activity_id: int) -> dict[str, Any]:
        published = reader.get("published")
        outcome_result = reader.get("outcome", "result")
        allowed = BASE_ATTRIBUTES | CLASS_ATTRIBUTES.get(class_uid, frozenset())

        candidate: dict[str, Any] = {
            "class_uid": class_uid,
            "category_uid": CLASS_CATEGORY_UID.get(class_uid, 0),
            "activity_id": activity_id,
            "type_uid": class_uid * 100 + activity_id,
            "time": _epoch_ms(published),
            "severity_id": SEVERITY_IDS.get(str(reader.get("severity") or "").upper(), 0),
            "status_id": _status_id(outcome_result),
            "metadata": {
                "version": self.ocsf_version,
                "uid": str(reader.get("uuid") or ""),
                "original_time": str(published) if published is not None else "",
                "product": {"name": "Okta System Log", "vendor_name": "Okta"},
                # The mapping revision travels with every record, so any row can
                # be traced to the rules that produced it (§3.1).
                "labels": [f"okta-ocsf-mapping:{self.mapping_version}"],
            },
        }

        message = reader.get("displayMessage")
        if message:
            candidate["message"] = str(message)
        if outcome_result:
            candidate["status"] = str(outcome_result).title()
        reason = reader.get("outcome", "reason")
        if reason:
            candidate["status_detail"] = str(reason)

        actor = self._actor(reader)
        if actor:
            candidate["user"] = actor
            candidate["actor"] = {"user": dict(actor)}

        endpoint = self._src_endpoint(reader)
        if endpoint:
            candidate["src_endpoint"] = endpoint
        user_agent = reader.get("client", "userAgent", "rawUserAgent")
        if user_agent:
            candidate["http_request"] = {"user_agent": str(user_agent)}

        session = reader.get("authenticationContext", "externalSessionId")
        if session:
            candidate["session"] = {"uid": str(session)}
        if class_uid == 3002:
            # at_least_one: [service, dst_endpoint] -- the org is the service when
            # the event names no application.
            target = _first_target(reader, {"AppInstance", "AppUser"})
            candidate["service"] = {"name": str(target.get("displayName") or self.service_name)}
            candidate["is_mfa"] = _is_mfa(reader)

        self._class_objects(reader, class_uid, candidate)
        body = {name: value for name, value in candidate.items() if name in allowed}
        _fill_required(body, class_uid)
        return body

    def _class_objects(self, reader: _Reader, class_uid: int, candidate: dict[str, Any]) -> None:
        """The one object each class requires, built from ``target[]``."""
        if class_uid == 3004:
            entity = _first_target(reader, None)
            candidate["entity"] = {
                "name": str(entity.get("displayName") or entity.get("alternateId") or "unknown"),
                "uid": str(entity.get("id") or ""),
                "type": str(entity.get("type") or ""),
            }
        elif class_uid == 3005:
            granted = _first_target(reader, {"AppInstance", "AppUser"})
            candidate["privileges"] = [
                str(granted.get("displayName") or granted.get("alternateId") or "unknown")
            ]
        elif class_uid == 3006:
            group = _first_target(reader, {"UserGroup"})
            candidate["group"] = {
                "name": str(group.get("displayName") or "unknown"),
                "uid": str(group.get("id") or ""),
            }

    def _actor(self, reader: _Reader) -> dict[str, Any]:
        user: dict[str, Any] = {}
        for source_key, target_key in (
            ("id", "uid"),
            ("displayName", "name"),
            ("alternateId", "email_addr"),
        ):
            value = reader.get("actor", source_key)
            if value:
                user[target_key] = str(value)
        return user

    def _src_endpoint(self, reader: _Reader) -> dict[str, Any]:
        endpoint: dict[str, Any] = {}
        address = reader.get("client", "ipAddress")
        if address:
            endpoint["ip"] = str(address)
        location = reader.get("client", "geographicalContext")
        if isinstance(location, dict):
            mapped = {
                "city": location.get("city"),
                "country": location.get("country"),
                "region": location.get("state"),
            }
            trimmed = {key: str(value) for key, value in mapped.items() if value}
            if trimmed:
                endpoint["location"] = trimmed
        return endpoint


@dataclass(slots=True)
class _Reader:
    """Reads the source record and remembers what it read, so whatever is left
    over can go to ``unmapped`` without a hand-maintained list."""

    source: dict[str, Any]
    consumed: set[tuple[str, ...]] = field(default_factory=set)

    def get(self, *path: str) -> Any:
        node: Any = self.source
        for key in path:
            if not isinstance(node, dict) or key not in node:
                return None
            node = node[key]
        self.consumed.add(path)
        return node


def _entry(value: Any, name: Any) -> dict[str, int]:
    """One table row, validated at load time.

    Construction may fail loudly -- a table naming an activity the class does not
    define is a packaging bug, caught before a single event is mapped. What must
    never fail is :meth:`OktaOcsfMapper.map`.
    """
    if not isinstance(value, dict) or "class_uid" not in value or "activity_id" not in value:
        raise ValueError(f"mapping entry {name!r} needs class_uid and activity_id")
    class_uid = int(value["class_uid"])
    activity_id = int(value["activity_id"])
    allowed = ACTIVITY_IDS.get(class_uid)
    if allowed is None:
        raise ValueError(f"mapping entry {name!r}: OCSF 1.3.0 has no class {class_uid}")
    if activity_id not in allowed:
        raise ValueError(
            f"mapping entry {name!r}: class {class_uid} has no activity_id {activity_id}"
        )
    return {"class_uid": class_uid, "activity_id": activity_id}


def _status_id(result: Any) -> int:
    if not result:
        return 0
    return STATUS_IDS.get(str(result).upper(), 99)


def _is_mfa(reader: _Reader) -> bool:
    step = reader.get("authenticationContext", "authenticationStep")
    provider = str(reader.get("authenticationContext", "credentialProvider") or "")
    return bool(step) or "FACTOR" in provider.upper()


def _first_target(reader: _Reader, types: set[str] | None) -> dict[str, Any]:
    """The first matching entry of ``target[]``, read *without* consuming it.

    An Okta event can name several targets and a class has room for at most one,
    so the array stays in ``unmapped`` whole. Marking it consumed would drop the
    entries no class object had a place for, which is the silent discarding
    §3.3 exists to prevent.
    """
    targets = reader.source.get("target")
    if not isinstance(targets, list):
        return {}
    for candidate in targets:
        if not isinstance(candidate, dict):
            continue
        if types is None or str(candidate.get("type") or "") in types:
            return candidate
    return {}


def _epoch_ms(published: Any) -> int:
    """Okta's ``published`` is an ISO 8601 string; OCSF ``time`` is epoch millis.

    An unparseable timestamp yields 0 rather than an exception: the event still
    reaches the sink with its original string under ``metadata.original_time``,
    which beats dropping it (§3.3).
    """
    if isinstance(published, int) and not isinstance(published, bool):
        return published
    if not isinstance(published, str) or not published:
        return 0
    try:
        parsed = datetime.fromisoformat(published.replace("Z", "+00:00"))
    except ValueError:
        return 0
    return int(parsed.timestamp() * 1000)


def _fill_required(body: dict[str, Any], class_uid: int) -> None:
    """Guarantee the objects the class marks required exist, however thin.

    A record missing ``user`` is invalid for Authentication whatever else it
    carries, and an invalid record helps nobody downstream.
    """
    for name in REQUIRED_OBJECTS.get(class_uid, ()):
        if body.get(name):
            continue
        body[name] = ["unknown"] if name == "privileges" else {"name": "unknown"}


def _leftovers(source: dict[str, Any], consumed: set[tuple[str, ...]]) -> dict[str, Any]:
    rest = copy.deepcopy(source)
    for path in sorted(consumed, key=len, reverse=True):
        node: Any = rest
        for key in path[:-1]:
            node = node.get(key) if isinstance(node, dict) else None
            if node is None:
                break
        if isinstance(node, dict):
            node.pop(path[-1], None)
    return _without_empties(rest)


def _without_empties(node: dict[str, Any]) -> dict[str, Any]:
    pruned: dict[str, Any] = {}
    for key, value in node.items():
        if isinstance(value, dict):
            nested = _without_empties(value)
            if nested:
                pruned[key] = nested
        elif value is not None and value != [] and value != "":
            pruned[key] = value
    return pruned
