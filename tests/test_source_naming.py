"""What the Security Lake custom sources are called, and why not simply OCSF.

The name is in the S3 prefix the sink writes and is what a Glue table binds to,
so it is not a label -- renaming one after a run has published objects means
rewriting them. AWS caps it at 20 characters, and three OCSF class names do not
fit under a four-character prefix. These tests hold both halves: the table is
complete with respect to the schema, and every name it derives can actually be
registered.

Synthetic throughout (CLAUDE.md invariant 5).
"""

from __future__ import annotations

import hashlib

import pytest

from ocsf_connector.ocsf import schema
from ocsf_connector.sinks.naming import (
    CLASS_SOURCES,
    MAX_SOURCE_NAME,
    SOURCE_NAME_PATTERN,
    check_source_names,
    source_name,
)

PREFIX = "okta"


def test_every_ocsf_class_has_exactly_one_custom_source() -> None:
    """The obligation that survived the split. A class with no entry has nowhere
    to be written; two classes sharing an entry merge two streams into one Glue
    table, and nothing downstream could tell them apart again."""
    assert CLASS_SOURCES[3002] == "authentication", "a floor, so the checks below ran"

    assert set(CLASS_SOURCES) == set(schema.CLASS_NAMES), (
        "a class the schema defines with no source name, or a source name for a "
        "class that does not exist"
    )
    names = list(CLASS_SOURCES.values())
    assert len(set(names)) == len(names)


def test_every_derived_name_can_actually_be_registered() -> None:
    """AWS: a custom source name must be 20 characters or fewer, so that the
    AmazonSecurityLake-Provider-{name}-{region} role it creates stays under 64.
    Three names were over before this table existed."""
    assert source_name(PREFIX, 3003) == "okta_session_authz", "a floor for the loop"
    assert MAX_SOURCE_NAME == 20, (
        "AWS's number, written down here rather than read from the module the "
        "loop below checks -- an expectation taken from the thing under test "
        "moves with it, and this one cannot fail"
    )

    for class_uid in CLASS_SOURCES:
        name = source_name(PREFIX, class_uid)
        assert len(name) <= 20, f"{name} is {len(name)} characters"
        assert SOURCE_NAME_PATTERN.fullmatch(name), f"{name} has a character AWS refuses"


def test_only_the_names_that_overflow_were_shortened() -> None:
    """The decision, stated as a test: keep OCSF's name wherever it fits.

    Reading the OCSF name and the source name side by side is what makes this
    fail for the right reason -- a future shortening of a name that fits would
    be caught here rather than passing quietly because it is also short.
    """
    for class_uid, ocsf_name in schema.CLASS_NAMES.items():
        overflows = len(f"{PREFIX}_{ocsf_name}") > MAX_SOURCE_NAME
        kept = CLASS_SOURCES[class_uid] == ocsf_name
        assert kept is not overflows, (
            f"class {class_uid}: OCSF calls it {ocsf_name!r}, the sink calls it "
            f"{CLASS_SOURCES[class_uid]!r}, and it "
            f"{'overflows' if overflows else 'fits'}"
        )

    assert {uid for uid, name in CLASS_SOURCES.items() if name != schema.CLASS_NAMES[uid]} == {
        3003,
        3004,
        3006,
    }, "exactly three classes needed shortening; a fourth means the prefix grew"


def test_a_prefix_that_overflows_is_refused_with_the_amount_to_cut() -> None:
    """'invalid source_name' would send a reader to the wrong string: the prefix
    is fine in isolation, and it is the longest derived name that fails.

    The amount has to be sufficient for *every* source, not just the one named,
    which is why the advice is measured against the longest derived name rather
    than the first one over -- so the second assertion here is the real one.
    """
    with pytest.raises(ValueError) as refused:
        check_source_names("oktadev")

    message = str(refused.value)
    assert "oktadev_account_change" in message, "names the source that broke, in full"
    assert "Shorten sink.source_name by 2" in message, "and says what to do about it"

    check_source_names("oktadev"[:-2])  # taking the advice has to be enough


def test_the_default_prefix_is_accepted() -> None:
    """The contrast case. A guard that refuses everything passes the test above
    just as happily as one that works."""
    check_source_names(PREFIX)


def test_a_prefix_with_a_character_aws_refuses_is_refused_here() -> None:
    """The pattern is `[\\w\\-\\_\\:\\.]*`, and the name is also a path segment:
    a slash would silently add a level to the partition prefix."""
    with pytest.raises(ValueError, match="not allowed"):
        check_source_names("okta/prod")


def test_the_names_are_pinned_so_a_rename_cannot_ride_along() -> None:
    """The catch-all, in the style of the schema and Parquet spine pins.

    A rename is not a rename: it is a new custom source, a new Glue table, and
    every object already written under the old prefix stranded where no
    registered source points. That should cost a deliberate test edit.
    """
    payload = tuple(sorted(CLASS_SOURCES.items()))
    digest = hashlib.sha256(repr(payload).encode()).hexdigest()[:12]

    assert digest == "814fd1e603f3", (
        f"the custom source names changed. If that was deliberate, update this to "
        f"{digest!r} and say in the commit message what happens to objects already "
        "published under the old names"
    )
