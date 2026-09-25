"""What a Security Lake custom source may be called.

One registered custom source per OCSF class (docs/SPEC.md §4.1), and the name is
not a free choice. It goes into the S3 prefix the sink writes and into the Glue
table a query binds to, so renaming one later means rewriting every object
already published under the old prefix. AWS also caps it:

    "You must use a CustomLogSource name that is shorter than or equal to 20
    characters. This ensures that the LogProviderRole name is below the 64
    character limit."
    -- CreateCustomLogSource, verified 2026-09-24 (docs/SPEC.md §8)

That cap is why this table is here rather than in ``ocsf/schema.py`` with the
rest of the class definitions. The source name *was* the OCSF class name, taken
straight from the schema so the two could not drift. Three of them do not fit:
``authorize_session`` and ``entity_management`` are 17 characters, which leaves
room for a two-character prefix and nothing else. So the name is an AWS-shaped
slug, not an OCSF fact, and bending OCSF's own class names to fit an AWS limit
would have made the schema lie about the version it describes.

The names below keep OCSF's wherever it fits and shorten only what overflows.
Deliberately not a uniform abbreviation: ``authn`` and ``authz`` as sibling
table names differ by one letter in a dropdown, and picking the wrong one is
silent -- the results still look plausible.
"""

from __future__ import annotations

import re

MAX_SOURCE_NAME = 20
"""AWS's cap on a custom source name, quoted above."""

SOURCE_NAME_PATTERN = re.compile(r"[\w\-:.]+")
"""``[\\w\\-\\_\\:\\.]*`` from the CreateCustomLogSource reference, requiring at
least one character since the name is also a path segment.

Bare rather than anchored, because the one place it is used anchors it with
``fullmatch``. Doing both is not free: two mechanisms enforcing one rule means
either can be removed without any input behaving differently, and a guard whose
weakening nothing can observe is the kind this project keeps finding by
mutation."""

CLASS_SOURCES: dict[int, str] = {
    0: "base_event",
    3001: "account_change",
    3002: "authentication",
    3003: "session_authz",  # OCSF authorize_session: 22 with the prefix
    3004: "entity",  # OCSF entity_management: 22 with the prefix
    3005: "user_access",
    3006: "group",  # OCSF group_management: 21 with the prefix
}
"""OCSF class uid -> the custom source its records are written to.

Every class the schema defines needs an entry: a class with no source name has
nowhere to go, and a class sharing another's name merges two streams into one
Glue table.
"""


def source_name(prefix: str, class_uid: int) -> str:
    """The registered custom source for ``class_uid``, under ``prefix``."""
    return f"{prefix}_{CLASS_SOURCES[class_uid]}"


def check_source_names(prefix: str) -> None:
    """Refuse a prefix that cannot be registered, before anything is written.

    Called when configuration loads, which is the last moment this is cheap.
    ``sink.source_name`` is configurable, so the alternative is discovering it
    at registration -- or worse, after a run has published objects under a
    prefix no custom source can ever be created for, since the prefix is in the
    key and the key is what a replay must reproduce (§5.2).

    Raises :class:`ValueError` naming the offending source and the limit it
    broke, because "invalid source_name" sends a reader to the wrong string: the
    prefix is fine in isolation and it is the longest *derived* name that fails.
    """
    for class_uid in sorted(CLASS_SOURCES):
        name = source_name(prefix, class_uid)
        if not SOURCE_NAME_PATTERN.fullmatch(name):
            raise ValueError(
                f"custom source name {name!r} is not allowed: Security Lake accepts "
                f"word characters, hyphen, colon and dot (SPEC §4.1)"
            )

    # The longest one, not the first one over. Reporting whichever came first
    # would make the advice below wrong in the worst way -- an operator shortens
    # by the amount asked, and the next source along still does not fit.
    longest = max((source_name(prefix, uid) for uid in sorted(CLASS_SOURCES)), key=len)
    if len(longest) > MAX_SOURCE_NAME:
        raise ValueError(
            f"custom source name {longest!r} is {len(longest)} characters; Security "
            f"Lake allows {MAX_SOURCE_NAME}, so that the "
            f"AmazonSecurityLake-Provider-{{name}}-{{region}} role it creates stays "
            f"under 64 (SPEC §4.1). Shorten sink.source_name by "
            f"{len(longest) - MAX_SOURCE_NAME}"
        )
