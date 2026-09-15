"""Okta -> OCSF 1.3.0 mapping.

The rule under test is CLAUDE.md invariant 4: mapping never raises and never
drops. Everything else here guards the shape of what it emits, because a record
carrying an attribute its class does not define is invalid for that class.

Records are the synthetic fixtures (invariant 5).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ocsf_connector.mapping.okta import (
    ACTIVITY_IDS,
    BASE_ATTRIBUTES,
    CLASS_ATTRIBUTES,
    REQUIRED_OBJECTS,
    OktaOcsfMapper,
)

FIXTURES = Path(__file__).parent / "fixtures" / "okta"


@pytest.fixture(scope="module")
def mapper() -> OktaOcsfMapper:
    return OktaOcsfMapper()


def fixture_records() -> list[dict[str, Any]]:
    loaded: list[dict[str, Any]] = json.loads((FIXTURES / "system_log_page.json").read_text())
    return loaded


def record(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "uuid": "00000000-0000-4000-8000-000000000001",
        "published": "2026-09-05T00:00:01.000Z",
        "eventType": "user.session.start",
        "severity": "INFO",
        "displayMessage": "User login to Okta",
        "actor": {
            "id": "00usynthetic00000001",
            "displayName": "Alex Example",
            "alternateId": "alex.example@example.com",
            "type": "User",
        },
        "client": {
            "ipAddress": "192.0.2.10",
            "userAgent": {"rawUserAgent": "Mozilla/5.0 (Synthetic)"},
            "geographicalContext": {"city": "Exampleville", "country": "Exampleland"},
        },
        "outcome": {"result": "SUCCESS", "reason": None},
        "transaction": {"id": "synthetic-transaction-0001", "type": "WEB"},
        "debugContext": {"debugData": {"requestUri": "/api/v1/authn"}},
    }
    base.update(overrides)
    return base


# --- the worked example -----------------------------------------------------


def test_a_session_start_maps_to_the_spec_worked_example(mapper: OktaOcsfMapper) -> None:
    """docs/SPEC.md §3.3: user.session.start -> Authentication, activity 1."""
    event = mapper.map(record())

    assert event.class_uid == 3002
    assert event.uid == "00000000-0000-4000-8000-000000000001"
    assert event.time_ms == 1788566401000

    body = event.body
    assert body["category_uid"] == 3
    assert body["activity_id"] == 1
    assert body["type_uid"] == 300201, "type_uid = class_uid * 100 + activity_id"
    assert body["severity_id"] == 1
    assert body["status_id"] == 1
    assert body["status"] == "Success"
    assert body["metadata"]["version"] == "1.3.0"
    assert body["metadata"]["uid"] == event.uid
    assert body["metadata"]["original_time"] == "2026-09-05T00:00:01.000Z"
    assert body["metadata"]["event_code"] == "user.session.start"
    assert body["metadata"]["labels"] == [f"okta-ocsf-mapping:{mapper.mapping_version}"]
    assert body["user"] == {
        "uid": "00usynthetic00000001",
        "name": "Alex Example",
        "email_addr": "alex.example@example.com",
    }
    assert body["src_endpoint"]["ip"] == "192.0.2.10"
    assert body["src_endpoint"]["location"] == {"city": "Exampleville", "country": "Exampleland"}
    assert body["http_request"]["user_agent"] == "Mozilla/5.0 (Synthetic)"
    assert body["service"], "3002 constrains at_least_one: [service, dst_endpoint]"


def test_a_failure_outcome_becomes_status_id_2(mapper: OktaOcsfMapper) -> None:
    event = mapper.map(
        record(outcome={"result": "FAILURE", "reason": "INVALID_CREDENTIALS"}, severity="WARN")
    )

    assert event.body["status_id"] == 2
    assert event.body["status_detail"] == "INVALID_CREDENTIALS"
    assert event.body["severity_id"] == 3


def test_an_unrecognized_outcome_is_other_not_a_guess(mapper: OktaOcsfMapper) -> None:
    assert mapper.map(record(outcome={"result": "CHALLENGE"})).body["status_id"] == 99
    assert mapper.map(record(outcome={})).body["status_id"] == 0


# --- never raises, never drops ----------------------------------------------


def test_an_unknown_event_type_degrades_and_counts() -> None:
    """CLAUDE.md invariant 4. The counter is the source-drift alarm, so it has to
    fire on every occurrence, not just the first."""
    seen: list[str] = []
    mapper = OktaOcsfMapper(on_unmapped=seen.append)

    event = mapper.map(record(eventType="user.mysterious.new_thing"))
    mapper.map(record(eventType="user.mysterious.new_thing"))

    assert event.class_uid == 0, "Base Event, not a guessed IAM class"
    assert event.body["category_uid"] == 0
    assert event.body["activity_id"] == 0
    assert event.body["type_uid"] == 0
    assert event.body["metadata"]["event_code"] == "user.mysterious.new_thing", (
        "Base Event has no field naming the vendor's event type; this is where it lives"
    )
    assert "eventType" not in event.body["unmapped"], "and it is not duplicated there too"
    assert mapper.unmapped_event_types["user.mysterious.new_thing"] == 2
    assert seen == ["user.mysterious.new_thing"] * 2


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"eventType": "user.session.start"},
        {"eventType": None, "published": None, "uuid": None},
        {"published": "not a timestamp"},
        {"published": 12345},
        {"actor": "not an object", "client": [], "target": "not a list"},
        {"outcome": None, "severity": 17},
    ],
    ids=["empty", "only-type", "nulls", "bad-time", "int-time", "wrong-types", "odd-scalars"],
)
def test_mapping_never_raises(mapper: OktaOcsfMapper, bad: dict[str, Any]) -> None:
    event = mapper.map(bad)

    assert isinstance(event.time_ms, int)
    assert event.class_uid in ACTIVITY_IDS


def test_an_unparseable_timestamp_keeps_the_original(mapper: OktaOcsfMapper) -> None:
    event = mapper.map(record(published="the ides of March"))

    assert event.time_ms == 0
    assert event.body["metadata"]["original_time"] == "the ides of March"


def test_every_source_field_survives_somewhere(mapper: OktaOcsfMapper) -> None:
    """Fields that are not mapped go to unmapped, rather than being discarded."""
    event = mapper.map(record())

    unmapped = event.body["unmapped"]
    assert unmapped["transaction"]["id"] == "synthetic-transaction-0001"
    assert unmapped["debugContext"]["debugData"]["requestUri"] == "/api/v1/authn"
    assert "uuid" not in unmapped, "consumed fields are not duplicated into unmapped"
    assert "ipAddress" not in unmapped.get("client", {})


def test_targets_the_mapping_could_not_lift_still_reach_unmapped(
    mapper: OktaOcsfMapper,
) -> None:
    """A class has room for one target object; Okta names several. The array has
    to survive whole, or the extras are silently discarded (docs/SPEC.md §3.3)."""
    targets = [
        {"id": "00gsynthetic0001", "type": "UserGroup", "displayName": "Synthetic group"},
        {"id": "00usynthetic0002", "type": "User", "displayName": "Sam Example"},
    ]

    event = mapper.map(record(eventType="group.user_membership.add", target=targets))

    assert event.body["group"]["uid"] == "00gsynthetic0001", "one target was lifted"
    assert event.body["unmapped"]["target"] == targets, "and none of them were lost"


# --- shape of the output ----------------------------------------------------


@pytest.mark.parametrize(
    ("event_type", "class_uid", "activity_id"),
    [
        ("user.session.start", 3002, 1),
        ("user.lifecycle.suspend", 3001, 9),
        ("group.user_membership.add", 3006, 3),
        ("application.user_membership.add", 3005, 1),
        ("policy.rule.update", 3004, 3),
        ("security.request.blocked", 0, 99),
    ],
)
def test_table_entries_reach_the_event(
    mapper: OktaOcsfMapper, event_type: str, class_uid: int, activity_id: int
) -> None:
    event = mapper.map(record(eventType=event_type))

    assert (event.class_uid, event.body["activity_id"]) == (class_uid, activity_id)
    assert event.body["type_uid"] == class_uid * 100 + activity_id


def test_no_event_carries_an_attribute_its_class_does_not_define(
    mapper: OktaOcsfMapper,
) -> None:
    """The whole reason the per-class sets exist: Entity Management has no user,
    only Authentication has service/session/is_mfa."""
    for event_type in [*mapper._events, "user.unknown.thing"]:
        event = mapper.map(record(eventType=event_type))
        allowed = BASE_ATTRIBUTES | CLASS_ATTRIBUTES[event.class_uid]
        assert set(event.body) <= allowed, f"{event_type} emitted {set(event.body) - allowed}"


def test_required_objects_are_always_present(mapper: OktaOcsfMapper) -> None:
    """A record missing a required object is invalid for its class, so a thin
    placeholder beats omission."""
    for event_type in mapper._events:
        event = mapper.map({"eventType": event_type})
        for name in REQUIRED_OBJECTS[event.class_uid]:
            assert event.body.get(name), f"{event_type} has no {name}"


def test_entity_management_names_its_target(mapper: OktaOcsfMapper) -> None:
    event = mapper.map(
        record(
            eventType="policy.rule.update",
            target=[
                {"id": "0prsynthetic0001", "type": "PolicyRule", "displayName": "Synthetic rule"}
            ],
        )
    )

    assert event.body["entity"] == {
        "name": "Synthetic rule",
        "uid": "0prsynthetic0001",
        "type": "PolicyRule",
    }
    assert "user" not in event.body, "3004 defines entity, not user"


def test_group_membership_names_the_group(mapper: OktaOcsfMapper) -> None:
    event = mapper.map(
        record(
            eventType="group.user_membership.add",
            target=[
                {"id": "00gsynthetic0001", "type": "UserGroup", "displayName": "Synthetic group"},
                {"id": "00usynthetic0002", "type": "User", "displayName": "Sam Example"},
            ],
        )
    )

    assert event.body["group"] == {"name": "Synthetic group", "uid": "00gsynthetic0001"}
    assert event.body["user"]["uid"] == "00usynthetic00000001", "the actor, not the target"


# --- the table itself -------------------------------------------------------


def test_every_table_entry_is_legal_in_ocsf_1_3_0(mapper: OktaOcsfMapper) -> None:
    """Checked at load time; asserted here so the guard itself is covered."""
    for event_type, entry in mapper._events.items():
        allowed = ACTIVITY_IDS[entry["class_uid"]]
        assert entry["activity_id"] in allowed, f"{event_type} is not legal in 1.3.0"


@pytest.mark.parametrize(
    "row",
    [
        {"class_uid": 3002, "activity_id": 7},
        {"class_uid": 3007, "activity_id": 1},
        {"class_uid": 3002},
    ],
    ids=["activity-added-after-1.3.0", "class-added-after-1.3.0", "incomplete"],
)
def test_a_table_that_does_not_fit_the_target_version_fails_to_load(
    tmp_path: Path, row: dict[str, Any]
) -> None:
    table = tmp_path / "bad.yaml"
    table.write_text(
        "version: test\nocsf_version: '1.3.0'\n"
        "fallback: {class_uid: 0, activity_id: 0}\n"
        f"events:\n  some.event: {json.dumps(row)}\n"
    )

    with pytest.raises(ValueError):
        OktaOcsfMapper(table_path=table)


def test_the_recorded_fixture_maps(mapper: OktaOcsfMapper) -> None:
    events = [mapper.map(raw) for raw in fixture_records()]

    assert [event.class_uid for event in events] == [3002, 0]
    assert events[0].time_ms < events[1].time_ms
    assert mapper.unmapped_event_types["user.authentication.auth_via_mfa"] == 1
