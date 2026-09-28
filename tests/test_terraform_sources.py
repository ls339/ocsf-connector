"""The terraform's source names, held to the sink's.

The connector derives a custom source from the class it mapped and writes to
``ext/{source}/...``; the terraform registers the sources that prefix has to
match. Nothing in either language can see the other, so the two are one edit away
from disagreeing -- and the symptom of disagreement is objects arriving in the
bucket with no Glue table pointing at them, which from outside looks exactly like
a stream with nothing to ship (docs/SPEC.md §4.2).

So this reads the HCL as text. Not elegant, and cheaper than the alternatives: a
generated file someone forgets to regenerate, or a terraform run in CI, which
needs a provider download and credentials CI does not have.

Synthetic throughout: the file read here names classes, not tenants.
"""

from __future__ import annotations

import re
from pathlib import Path

from ocsf_connector.sinks.naming import CLASS_SOURCES

SOURCES_TF = Path(__file__).resolve().parent.parent / "terraform" / "sources.tf"

ENTRY = re.compile(r"^\s{4}(?P<suffix>\w+)\s*=\s*(?P<value>null|\"[A-Z_0-9]+\")\s*$", re.MULTILINE)


def declared() -> dict[str, str | None]:
    """The ``event_classes`` map, as {suffix: OCSF event class or None}."""
    body = SOURCES_TF.read_text()
    block = body.split("event_classes = {", 1)[1].split("\n  }", 1)[0]
    return {
        match["suffix"]: None if match["value"] == "null" else match["value"].strip('"')
        for match in ENTRY.finditer(block)
    }


def test_the_terraform_registers_exactly_the_sources_the_sink_writes() -> None:
    """One registered source per class, and no source for a class that does not
    exist. A missing entry is a class whose objects no table points at; a spare
    one is a Glue table nothing ever writes to, which looks like a broken
    connector on whichever dashboard counts sources."""
    found = declared()

    assert found["authentication"] == "AUTHENTICATION", "a floor: the map parsed at all"
    assert set(found) == set(CLASS_SOURCES.values()), (
        "terraform/sources.tf and sinks/naming.py disagree about which custom sources exist"
    )


def test_base_event_declares_no_event_class() -> None:
    """Not an omission. Unknown event types degrade to Base Event (invariant 4),
    and Base Event is absent from the event classes AWS accepts -- so the source
    is registered without one, and the first apply answers whether that is
    allowed (§4.2)."""
    assert declared()["base_event"] is None


def test_every_other_source_declares_one_event_class_in_aws_spelling() -> None:
    """AWS's enum is UPPER_SNAKE and its pattern is ``[A-Z\\_0-9]*``; a
    lowercase OCSF class name would be refused at apply."""
    classes = {suffix: value for suffix, value in declared().items() if value is not None}

    assert len(classes) == len(CLASS_SOURCES) - 1, "one class each, Base Event aside"
    for suffix, event_class in classes.items():
        assert re.fullmatch(r"[A-Z_0-9]+", event_class), f"{suffix} => {event_class}"
