"""The OCSF 1.3.0 schema, guarded independently of the code that reads it.

These assertions deliberately restate the schema in literal form rather than
deriving anything from :mod:`ocsf_connector.ocsf.schema`. That is the whole
point. The mapper filters its output *through* ``CLASS_ATTRIBUTES`` and fills
required objects *from* ``REQUIRED_OBJECTS``, so a test that checks the mapper
against those same constants passes no matter what they say: corrupt the schema
and both sides move together. Emptying ``REQUIRED_OBJECTS[3004]`` even makes
``test_required_objects_are_always_present`` pass vacuously, its loop body never
running.

Found by mutating the YAML once the schema became data. The values below were
read from the OCSF 1.3.0 schema browser on 2026-09-12 and are the version
Security Lake accepts (docs/SPEC.md §3.1); 1.3.0 differs from current OCSF in
ways that change what is legal to emit.
"""

from __future__ import annotations

import hashlib

from ocsf_connector.ocsf import schema

CLASSES = {
    0: "base_event",
    3001: "account_change",
    3002: "authentication",
    3003: "authorize_session",
    3004: "entity_management",
    3005: "user_access",
    3006: "group_management",
}

EXPECTED_BASE_ATTRIBUTES = frozenset(
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


def test_the_schema_describes_the_classes_1_3_0_defines() -> None:
    """Base Event plus the six IAM classes. 1.3.0's IAM category ends at 3006:
    3007 and 3008 arrive later, and emitting one would be invalid here."""
    assert schema.VERSION == "1.3.0"
    assert schema.CLASS_SOURCES == CLASSES


def test_each_class_sits_in_the_category_1_3_0_puts_it_in() -> None:
    """Base Event is category 0; every IAM class is category 3. ``category_uid``
    is written to every record and partitions nothing by accident."""
    assert schema.CLASS_CATEGORY_UID == {
        0: 0,
        3001: 3,
        3002: 3,
        3003: 3,
        3004: 3,
        3005: 3,
        3006: 3,
    }


def test_the_attributes_that_actually_distinguish_the_classes() -> None:
    """Spelled out because the mapper's per-class filter silently drops anything
    a class does not name: remove ``is_mfa`` from 3002 and the field simply stops
    appearing in Security Lake, with every test still green."""

    def defines(name: str) -> set[int]:
        return {uid for uid, attrs in schema.CLASS_ATTRIBUTES.items() if name in attrs}

    assert defines("is_mfa") == {3002}, "only Authentication"
    assert defines("service") == {3002}
    assert defines("session") == {3002, 3003}
    assert defines("entity") == {3004}, "and Entity Management alone"
    assert defines("user") == {3001, 3002, 3003, 3005, 3006}, "every IAM class but 3004"
    assert defines("privileges") == {3003, 3005, 3006}
    assert defines("group") == {3003, 3006}
    assert schema.CLASS_ATTRIBUTES[0] == frozenset(), "Base Event adds nothing to the base"


def test_no_class_names_an_activity_1_3_0_does_not_have() -> None:
    """The load-time guard in the mapper rejects a table entry naming an illegal
    activity -- which makes this list the thing deciding what is legal."""
    assert schema.ACTIVITY_IDS[3002] == frozenset({0, 1, 2, 3, 4, 5, 6, 99}), (
        "no activity 7 (Account Switch) until after 1.3.0"
    )
    assert schema.ACTIVITY_IDS[3003] == frozenset({0, 1, 2, 99})
    assert schema.ACTIVITY_IDS[3005] == frozenset({0, 1, 2, 99})
    assert schema.ACTIVITY_IDS[0] == frozenset({0, 99}), "Base Event: Unknown and Other"

    for uid, activities in schema.ACTIVITY_IDS.items():
        assert 0 in activities and 99 in activities, f"{uid} needs Unknown and Other"


def test_the_objects_each_class_requires() -> None:
    """A record missing one is invalid for its class, so the mapper fills a thin
    placeholder. An empty list here means no placeholder and no complaint."""
    assert schema.REQUIRED_OBJECTS == {
        0: (),
        3001: ("user",),
        3002: ("user",),
        3003: ("user",),
        3004: ("entity",),
        3005: ("user", "privileges"),
        3006: ("group",),
    }


def test_the_base_attributes_every_class_carries() -> None:
    assert schema.BASE_ATTRIBUTES == EXPECTED_BASE_ATTRIBUTES


def test_every_class_has_its_own_custom_source() -> None:
    """One registered Security Lake source per class (§4.1), and the name is part
    of the object key -- two classes sharing one would merge two streams."""
    names = list(schema.CLASS_SOURCES.values())

    assert len(set(names)) == len(names)
    for name in names:
        assert name.replace("_", "").isalnum() and name.islower(), f"{name} is not a source slug"


def test_the_schema_is_pinned_so_it_cannot_drift_quietly() -> None:
    """The catch-all, in the style of the mapping table's version pin.

    Every value above is load-bearing somewhere, and the per-field tests only
    cover what somebody thought to write down. This fails on *any* edit to the
    schema, which is the intent: changing what the connector emits should be a
    deliberate act with a test change attached, not a YAML tweak that rides
    along in an unrelated commit.
    """
    entries = sorted(
        (
            uid,
            schema.CLASS_SOURCES[uid],
            schema.CLASS_CATEGORY_UID[uid],
            tuple(sorted(schema.ACTIVITY_IDS[uid])),
            tuple(sorted(schema.CLASS_ATTRIBUTES[uid])),
            schema.REQUIRED_OBJECTS[uid],
        )
        for uid in schema.CLASS_SOURCES
    )
    payload = (schema.VERSION, tuple(sorted(schema.BASE_ATTRIBUTES)), entries)
    digest = hashlib.sha256(repr(payload).encode()).hexdigest()[:12]

    assert digest == "811cdebd6c7a", (
        f"the OCSF schema changed. If that was deliberate, update this to {digest!r} "
        "and say in the commit message which OCSF version the connector now emits"
    )
