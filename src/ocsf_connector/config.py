"""Configuration: a TOML file, with environment variables allowed to win.

Two rules shape this module.

**Secrets are named here, never written here.** The config file holds the *path*
to a private key, not the key. A repository of security-adjacent tooling that
invites people to paste PEMs into a checked-in file has already lost (§2.4).

**Tail's ``since`` has no default, and never will.** It is required, and it comes
from this file or the environment -- never from ``now()``. That is not a
preference: docs/SPEC.md §5.2 shows the duplicate Security Lake object a moving
opening cursor produces after a crash before the first commit. A default here
would quietly reintroduce it, so the absence of one is load-bearing.

Environment overrides are an explicit table rather than a naming convention,
because a convention means an operator cannot answer "which variable sets this?"
without reading the loader.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ENV_OVERRIDES: dict[str, tuple[str, ...]] = {
    "OCSF_OKTA_ORG_URL": ("okta", "org_url"),
    "OCSF_OKTA_CLIENT_ID": ("okta", "client_id"),
    "OCSF_OKTA_KID": ("okta", "kid"),
    "OCSF_OKTA_PRIVATE_KEY_FILE": ("okta", "private_key_file"),
    "OCSF_OKTA_DPOP_KEY_FILE": ("okta", "dpop_key_file"),
    "OCSF_OKTA_SINCE": ("okta", "since"),
    "OCSF_SINK_DIRECTORY": ("sink", "directory"),
    "OCSF_SINK_REGION": ("sink", "region"),
    "OCSF_SINK_ACCOUNT_ID": ("sink", "account_id"),
    "OCSF_SINK_SOURCE_NAME": ("sink", "source_name"),
    "OCSF_STATE_DATABASE": ("state", "database"),
    "OCSF_TELEMETRY_ENABLED": ("telemetry", "enabled"),
    "OCSF_STREAM": ("stream",),
}
"""Environment variable -> path into the config document. Every override the
connector understands, in one greppable place."""


class MissingConfig(ValueError):
    """A setting this mode needs was not supplied.

    Its own type rather than a bare ``ValueError`` so the CLI can tell it apart
    from the runtime ones -- the cursor origin check raises ``ValueError`` too,
    and reporting a refused cursor as a configuration mistake would send an
    operator looking in entirely the wrong place.
    """


class Strict(BaseModel):
    """Unknown keys are an error.

    A typo in a config file is otherwise a setting that silently does nothing,
    which is the worst way to learn that a connector was not doing what you
    asked.
    """

    model_config = ConfigDict(extra="forbid")


class OktaConfig(Strict):
    org_url: str
    client_id: str
    kid: str
    """Which registered key signed the assertion. Two may be valid during a
    rollover (§2.4)."""
    private_key_file: Path
    """Path to the PEM, read once at startup. Never the key itself."""
    dpop_key_file: Path | None = None
    """Present means the app requires DPoP, and this is its *separate* key
    pair -- Okta requires a different one from client authentication (§2.4)."""
    since: str | None = None
    """Tail's opening bound, and tail's alone -- backfill takes its bounds as
    arguments.

    Optional here, required by :func:`~ocsf_connector.runner.modes.tail`, which
    refuses to start without it. Note what has *not* changed: there is still no
    default value. The §5.2 guarantee was never about the field being mandatory,
    it was about nobody being able to supply a plausible one -- a
    ``now() - 1 hour`` here would reintroduce the moving opening cursor in
    silence. ``None`` cannot be mistaken for a real bound.
    """
    limit: int = Field(default=1000, ge=1, le=1000)
    poll_seconds: float = Field(default=10.0, gt=0)
    """How long tail sleeps on an empty page. Okta's per-token budget is the
    real ceiling (§2.3); this only decides how eagerly an idle stream asks."""


class SinkConfig(Strict):
    kind: Literal["local"] = "local"
    """Only local for now. S3 delivery is its own issue, and pretending the
    option exists would be worse than admitting it does not."""
    directory: Path = Path("out")
    source_name: str = "okta"
    """Prefixes the per-class custom source names: okta_authentication, ... (§4.1)."""
    region: str
    account_id: str
    """``external_{okta_org_id}``: Okta events belong to no AWS account (§4.1)."""


class StateConfig(Strict):
    database: Path = Path("state/ocsf-connector.db")
    ttl_hours: float = Field(default=24.0, gt=0)


class TelemetryConfig(Strict):
    enabled: bool = False
    """Off by default. The connector must never need an observability stack in
    order to run (§7)."""


class Config(Strict):
    okta: OktaConfig
    sink: SinkConfig
    state: StateConfig = StateConfig()
    telemetry: TelemetryConfig = TelemetryConfig()
    stream: str | None = None
    """Overrides the per-mode default. Tail and backfill must not share one:
    the store is keyed by stream, so they would fight over a single cursor."""


def load_config(path: Path, env: Mapping[str, str] | None = None) -> Config:
    """Read ``path``, apply environment overrides, validate."""
    with path.open("rb") as handle:
        document: dict[str, Any] = tomllib.load(handle)
    _apply_env(document, os.environ if env is None else env)
    return Config.model_validate(document)


def _apply_env(document: dict[str, Any], env: Mapping[str, str]) -> None:
    for variable, location in ENV_OVERRIDES.items():
        value = env.get(variable)
        if value is None:
            continue
        node = document
        for key in location[:-1]:
            child = node.get(key)
            if not isinstance(child, dict):
                child = {}
                node[key] = child
            node = child
        # Left as the string it arrived as. pydantic does the conversion,
        # including the one that actually matters -- "false" becomes False, not a
        # non-empty string that every truthiness test would call True. Verified
        # against pydantic 2.13 for true/false/1/0/yes/no. A hand-written
        # coercion sat here first and protected nothing; a mutation that deleted
        # it changed no behavior, which is how it was found.
        node[location[-1]] = value
