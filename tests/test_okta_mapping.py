"""Okta -> OCSF 1.3.0 mapping.

The rule under test is CLAUDE.md invariant 4: mapping never raises and never
drops. Everything else here guards the shape of what it emits, because a record
carrying an attribute its class does not define is invalid for that class.

Records are the synthetic fixtures (invariant 5).
"""

from __future__ import annotations

import hashlib
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
    assert body["is_mfa"] is False, (
        "3002 defines is_mfa, so it is emitted even when false. Asserted here "
        "because the per-class filter test cannot see this: drop is_mfa from the "
        "schema and the mapper stops emitting it, which is still a subset of what "
        "the class allows"
    )


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
        ("app.oauth2.token.grant", 3002, 4),
        ("app.oauth2.token.grant.access_token", 3002, 4),
        ("app.oauth2.token.grant.refresh_token", 3002, 5),
        ("app.oauth2.authorize.code", 3002, 3),
    ],
)
def test_table_entries_reach_the_event(
    mapper: OktaOcsfMapper, event_type: str, class_uid: int, activity_id: int
) -> None:
    event = mapper.map(record(eventType=event_type))

    assert (event.class_uid, event.body["activity_id"]) == (class_uid, activity_id)
    assert event.body["type_uid"] == class_uid * 100 + activity_id


@pytest.mark.parametrize(
    ("event_type", "class_uid", "activity_id"),
    [
        ("user.authentication.auth_via_mfa", 3002, 6),
        ("user.authentication.verify", 3002, 6),
        ("app.oauth2.token.grant.id_token", 3002, 99),
        ("policy.evaluate_sign_on", 0, 99),
        ("user.session.access_admin_app", 0, 99),
    ],
)
def test_the_five_types_a_live_org_emits_are_classified_deliberately(
    mapper: OktaOcsfMapper, event_type: str, class_uid: int, activity_id: int
) -> None:
    """The decision recorded in docs/SPEC.md §3.3, asserted as data.

    A live org emits all five and none of them had a mapping, because the obvious
    one was wrong: activity 1 Logon on any of the first three double-counts
    sign-ins against user.session.start. The MFA pair is 6 Preauth -- the 1.3.0
    vocabulary for proving identity before the ticket is granted, which is what an
    MFA challenge is -- and an ID token is Other, being an assertion about who
    somebody is rather than a ticket for reaching a service. The last two are not
    authentication at all and stay in Base Event.
    """
    event = mapper.map(record(eventType=event_type))

    assert (event.class_uid, event.body["activity_id"]) == (class_uid, activity_id)


def test_no_new_mapping_added_a_second_logon_to_a_single_sign_in() -> None:
    """The constraint the five were held up for, stated so it cannot quietly
    stop being true: exactly two event types mean "somebody logged in", and one
    sign-in produces one of them. Anything else arriving at activity 1 inflates
    every count of logons in Athena, which is the number people look at first."""
    mapper = OktaOcsfMapper()

    logons = {
        event_type
        for event_type, (class_uid, activity_id) in mapper.event_rules().items()
        if (class_uid, activity_id) == (3002, 1)
    }

    assert logons == {"user.session.start", "user.authentication.sso"}, (
        "a sign-in to Okta and an SSO assertion to a downstream app are two "
        "genuine logons; a third member here is almost certainly a step *within* "
        "one of them"
    )


DELIBERATE_BASE_EVENT = {
    # Not identity events, and no OCSF 1.3.0 IAM class claims them. Each is in
    # the table on purpose rather than left to the fallback, so that
    # unmapped_event_type_total keeps meaning "Okta emitted something new".
    "security.request.blocked",
    "policy.evaluate_sign_on",
    "user.session.access_admin_app",
    "application.provision.user.push",
    "application.provision.user.sync",
    "application.provision.user.push_profile",
    "app.user_management.push_new_user_success",
    "app.app_instance.provision_sync_job.started",
    "app.app_instance.provision_sync_job.completed",
    "security.protected_action.attempt",
    "system.email.delivery",
    "user.session.context.change",
}


def test_the_types_deliberately_left_at_base_event_are_exactly_these(
    mapper: OktaOcsfMapper,
) -> None:
    """Restated literally, because a missing entry is invisible otherwise.

    An event type dropped from this group still reaches Base Event -- through the
    fallback, at activity 0 instead of 99 -- so nothing about the delivered object
    looks wrong. What changes is that it starts incrementing
    unmapped_event_type_total again, putting a floor back under the drift alarm.

    The version digest would catch the edit, but its message invites updating the
    digest; this one names what left. Found by mutation: removing
    system.email.delivery passed every other test in this file.
    """
    at_base_event = {name for name, (cls, _) in mapper.event_rules().items() if cls == 0}

    assert at_base_event == DELIBERATE_BASE_EVENT
    for name in at_base_event:
        assert mapper.event_rules()[name] == (0, 99), (
            f"{name} is at Base Event but not at activity 99 Other -- 0 Unknown is "
            "what the fallback uses, so it would read as an accident"
        )


def test_privileges_granted_to_an_application_are_not_user_access(
    mapper: OktaOcsfMapper,
) -> None:
    """The rule that decides a whole family of events (pet.25).

    User Access Management requires a `user`, so putting an OAuth client's
    consent grant there would mean a placeholder person standing in for a
    machine -- and any report counting who was granted privileges would count
    applications as people. Granting privileges *to* an app is a change to that
    app, which is Entity Management.
    """
    rules = mapper.event_rules()

    assert rules["user.account.privilege.grant"] == (3005, 1), "a person: Assign Privileges"
    assert rules["app.oauth2.admin.consent.grant"][0] == 3004, "an application: Entity Update"
    assert rules["app.oauth2.client.privilege.grant"][0] == 3004

    granted_to_people = {
        name for name, (cls, _) in rules.items() if cls == 3005 and "oauth2" in name
    }
    assert granted_to_people == set(), f"OAuth clients reached 3005: {granted_to_people}"


def test_enabling_a_factor_and_using_one_are_different_events(
    mapper: OktaOcsfMapper,
) -> None:
    """Enrolment is an account change; verification is part of a sign-in.

    Conflating them would make every sign-in look like a factor enrolment, which
    is the mirror of the double-count pet.15 avoided in the other direction.
    """
    rules = mapper.event_rules()

    assert rules["user.mfa.factor.activate"] == (3001, 10), "MFA Factor Enable"
    assert rules["system.mfa.factor.activate"] == (3001, 10)
    assert rules["user.authentication.auth_via_mfa"] == (3002, 6), "Preauth, during a sign-in"


def test_reading_a_client_secret_is_classified_rather_than_buried(
    mapper: OktaOcsfMapper,
) -> None:
    """Low volume, high interest: somebody read a client secret.

    Entity Management is the only one of the six IAM classes with a Read
    activity, which is what makes this a queryable fact instead of a JSON string
    inside an `unmapped` column.
    """
    assert mapper.event_rules()["app.oauth2.client.read_client_secret"] == (3004, 2)


def test_devices_are_treated_as_entities(mapper: OktaOcsfMapper) -> None:
    """Arguable, and decided: a device is not an identity object, but Entity
    Management is the only class with Enroll, and device enrolment is exactly
    that. The alternative was Base Event, which says less for no more honesty."""
    rules = mapper.event_rules()

    assert rules["device.enrollment.create"] == (3004, 6), "Enroll"
    assert rules["device.lifecycle.activate"] == (3004, 10), "Activate"
    assert rules["device.user.add"] == (3004, 3), "Update"


def test_a_decided_event_type_does_not_register_as_source_drift() -> None:
    """Why the five are in the table rather than left to the fallback.

    Both produce the same object for Base Event cases -- same source, same
    prefix, same table -- so the difference is the alarm. Left out, every
    occurrence increments unmapped_event_type_total, and five known types ringing
    forever leave it no way to say "Okta emitted something new" (§7). Its own
    mapper, because it asserts a count.
    """
    mapper = OktaOcsfMapper()

    for event_type in (
        "user.authentication.auth_via_mfa",
        "user.authentication.verify",
        "app.oauth2.token.grant.id_token",
        "policy.evaluate_sign_on",
        "user.session.access_admin_app",
    ):
        mapper.map(record(eventType=event_type))

    assert mapper.unmapped_event_types == {}, "a decision is not drift"


def test_no_event_carries_an_attribute_its_class_does_not_define(
    mapper: OktaOcsfMapper,
) -> None:
    """The whole reason the per-class sets exist: Entity Management has no user,
    only Authentication has service/session/is_mfa."""
    rules = mapper.event_rules()
    # A loop over an empty table passes without running its body, which is the
    # failure mode this project has already been bitten by twice. One known
    # entry proves the loop ran; the table's size is the version pin's job.
    assert "user.session.start" in rules
    for event_type in [*rules, "user.unknown.thing"]:
        event = mapper.map(record(eventType=event_type))
        allowed = BASE_ATTRIBUTES | CLASS_ATTRIBUTES[event.class_uid]
        assert set(event.body) <= allowed, f"{event_type} emitted {set(event.body) - allowed}"


def test_required_objects_are_always_present(mapper: OktaOcsfMapper) -> None:
    """A record missing a required object is invalid for its class, so a thin
    placeholder beats omission."""
    rules = mapper.event_rules()
    assert "user.session.start" in rules  # not a vacuous loop -- see above
    for event_type in rules:
        event = mapper.map({"eventType": event_type})
        for name in REQUIRED_OBJECTS[event.class_uid]:
            assert event.body.get(name), f"{event_type} has no {name}"


def test_an_application_actor_does_not_become_a_user(mapper: OktaOcsfMapper) -> None:
    """An OAuth client-credentials grant acts as the *app*. Copying that into
    OCSF `user` puts applications in the identity lake, where anyone counting
    distinct users or alerting on user behavior sees machine traffic.

    Found on the first live backfill, and only reachable because the OAuth family
    now maps to 3002 -- before that these were Base Event and carried no user.
    """
    event = mapper.map(
        record(
            eventType="app.oauth2.token.grant.access_token",
            actor={
                "id": "0oasynthetic-app",
                "type": "PublicClientApp",
                "displayName": "Synthetic Service App",
                "alternateId": "unknown",
            },
        )
    )

    assert event.body["user"] == {"name": "unknown"}, "the class placeholder, not the app"
    assert "actor" not in event.body, "and no actor.user either"
    assert event.body["unmapped"]["actor"]["displayName"] == "Synthetic Service App", (
        "the real actor is preserved, just not as a person"
    )


def test_oktas_unknown_placeholder_never_becomes_an_email(mapper: OktaOcsfMapper) -> None:
    """`alternateId` is "unknown" when Okta has none. It is not an address."""
    event = mapper.map(record(actor={"id": "00usynth", "type": "User", "alternateId": "unknown"}))

    assert event.body["user"] == {"uid": "00usynth"}
    assert "email_addr" not in event.body["user"]


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


def test_the_table_version_moves_with_the_table() -> None:
    """The revision rides in metadata.labels on every record, so a changed table
    under a stale version mislabels everything it produces -- and the label is
    the only way to trace a row in Security Lake back to the rules behind it
    (docs/SPEC.md §3.1).

    Nothing asserted this until a mutation that froze the version while adding
    entries passed the whole suite. The version is pinned against a digest of
    the entries: change one without the other and this fails, which is the
    point.
    """
    mapper = OktaOcsfMapper()
    entries = sorted(
        (name, class_uid, activity_id)
        for name, (class_uid, activity_id) in mapper.event_rules().items()
    )
    digest = hashlib.sha256(repr(entries).encode()).hexdigest()[:12]

    assert (mapper.mapping_version, digest) == ("okta-2026.10.12", "586c17699046"), (
        "the table and its version must change together: update both, including "
        f"this assertion, to {mapper.mapping_version!r} / {digest!r}"
    )


def test_every_table_entry_is_legal_in_ocsf_1_3_0(mapper: OktaOcsfMapper) -> None:
    """Checked at load time; asserted here so the guard itself is covered."""
    for event_type, (class_uid, activity_id) in mapper.event_rules().items():
        allowed = ACTIVITY_IDS[class_uid]
        assert activity_id in allowed, f"{event_type} is not legal in 1.3.0"


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


def test_the_recorded_fixture_maps() -> None:
    """Builds its own mapper rather than taking the module-scoped one.

    It asserts a drift *count*, and the shared mapper accumulates across every
    test that touches it -- so the number was only ever right by accident of
    ordering. A second test mapping the same event type is enough to break it,
    which is exactly what happened.
    """
    mapper = OktaOcsfMapper()
    events = [mapper.map(raw) for raw in fixture_records()]

    assert [event.class_uid for event in events] == [3002, 3002]
    assert [event.body["activity_id"] for event in events] == [1, 6], (
        "a sign-in and the MFA step inside it: one Logon, one Preauth"
    )
    assert events[0].time_ms < events[1].time_ms
    assert mapper.unmapped_event_types == {}, (
        "both types in the fixture are mapped now. The drift counter's own "
        "behaviour is test_an_unknown_event_type_degrades_and_counts's job, on a "
        "type that really is unknown"
    )
