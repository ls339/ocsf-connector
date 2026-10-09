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

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ocsf_connector.sinks.naming import all_source_names, check_source_names

ENV_OVERRIDES: dict[str, tuple[str, ...]] = {
    "OCSF_OKTA_ORG_URL": ("okta", "org_url"),
    "OCSF_OKTA_CLIENT_ID": ("okta", "client_id"),
    "OCSF_OKTA_KID": ("okta", "kid"),
    "OCSF_OKTA_PRIVATE_KEY_FILE": ("okta", "private_key_file"),
    "OCSF_OKTA_DPOP_KEY_FILE": ("okta", "dpop_key_file"),
    "OCSF_OKTA_SINCE": ("okta", "since"),
    "OCSF_SINK_KIND": ("sink", "kind"),
    "OCSF_SINK_DIRECTORY": ("sink", "directory"),
    "OCSF_SINK_BUCKET": ("sink", "bucket"),
    "OCSF_SINK_EXTERNAL_ID": ("sink", "external_id"),
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
    kind: Literal["local", "s3"] = "local"
    """Where finished objects go. ``local`` writes files, which is how the
    partition layout is inspected without deploying anything (§4); ``s3`` puts
    them in a bucket, which is the only one that delivers."""
    directory: Path = Path("out")
    """Where ``local`` writes. Ignored by ``s3``."""
    bucket: str | None = None
    """Where ``s3`` writes. Required by that kind, and refused by the other --
    a bucket named beside ``kind = "local"`` means someone believes this run is
    delivering when it is not."""
    provider_roles: dict[str, str] = Field(default_factory=dict)
    """Custom source name -> the role Security Lake created to write it.

    From ``terraform output provider_roles``, not derived: AWS documents the role
    name but an ARN may carry a path, and a guessed path fails at the first PUT
    rather than at startup (§4.2). Empty means the caller's own credentials, which
    is what a plain bucket accepts and a registered source does not."""
    external_id: str | None = None
    """The external id those roles trust. Not a secret in AWS's sense, and still
    the thing that stops whoever learns a role ARN from assuming it, so it belongs
    in the environment rather than in a file committed anywhere."""
    source_name: str = "okta"
    """Prefixes the per-class custom source names: okta_authentication, ... (§4.1)."""
    region: str
    account_id: str
    """``external_{okta_org_id}``: Okta events belong to no AWS account (§4.1)."""

    def describe(self) -> str:
        """Where objects actually go, for the line an operator reads first.

        It used to print ``directory`` whatever the kind, so a run delivering to
        S3 announced that it was writing to a folder. That is the same mistake
        this class refuses in the other direction -- a bucket beside
        ``kind = "local"`` -- and it is worse here, because the startup line is
        what somebody reads during an incident to work out where the data went.
        """
        if self.kind == "s3":
            return f"s3://{self.bucket}"
        return str(self.directory)

    @field_validator("source_name")
    @classmethod
    def _registrable(cls, value: str) -> str:
        """Refuse a prefix whose derived source names cannot be registered.

        Checked here because this is the last cheap moment. The prefix is in the
        object key, the key is what a replay must reproduce (§5.2), and the
        derived name is what a Glue table binds to -- so a prefix that overflows
        AWS's cap is not a mistake you want to find at registration, still less
        after a run has published objects under it. The rule itself belongs to
        the sink, which owns the names; this only decides when to ask.
        """
        check_source_names(value)
        return value

    @model_validator(mode="after")
    def _destination_matches_kind(self) -> SinkConfig:
        """Each kind needs its own destination, and only its own.

        Refusing a stray ``bucket`` beside ``kind = "local"`` is the half that
        matters. A connector configured with a bucket it never writes to looks
        exactly like one that delivers, and the only way to tell from outside is
        to notice that the bucket stays empty -- which is also what a healthy
        idle stream looks like (§7).
        """
        if self.kind == "s3" and not self.bucket:
            raise ValueError('sink.kind = "s3" needs sink.bucket: there is nowhere to put objects')
        if self.provider_roles and self.kind != "s3":
            raise ValueError(
                'sink.provider_roles is set but sink.kind is not "s3", so nothing assumes '
                "them. Delete them, or deliver"
            )
        if self.provider_roles and not self.external_id:
            raise ValueError(
                "sink.provider_roles needs sink.external_id: the roles trust a principal "
                "presenting that id, and without it every assume-role is refused (§4.2)"
            )
        if self.external_id and not self.provider_roles:
            raise ValueError(
                "sink.external_id is set but no sink.provider_roles are, so it is never "
                "presented to anything"
            )
        expected = all_source_names(self.source_name)
        if self.provider_roles and set(self.provider_roles) != expected:
            missing = sorted(expected - set(self.provider_roles))
            spare = sorted(set(self.provider_roles) - expected)
            raise ValueError(
                "sink.provider_roles must name every custom source this connector "
                f"writes and no others. Missing: {missing or 'none'}. Not written by "
                f"this connector: {spare or 'none'}. A missing role is a class whose "
                "objects have nowhere to go; a spare one usually means source_name here "
                "and in terraform disagree (§4.2)"
            )
        if self.kind == "local" and self.bucket is not None:
            raise ValueError(
                'sink.bucket is set but sink.kind = "local", so nothing is delivered to it. '
                'Set kind = "s3" to deliver, or drop the bucket to say plainly that this run '
                "writes to a directory"
            )
        return self


class StateConfig(Strict):
    database: Path = Field(default=Path("state/ocsf-connector.db"), validate_default=True)
    """``validate_default`` because the default is the case that matters.

    pydantic skips validators on defaults unless asked, and the relative default
    is precisely the value that causes the trouble -- an operator who sets this
    explicitly has usually typed an absolute path already. Without the flag the
    pinning below would run only for configurations that did not need it.
    """
    ttl_hours: float = Field(default=24.0, gt=0)

    @field_validator("database")
    @classmethod
    def _absolute(cls, value: Path) -> Path:
        """Pin the path at load time.

        Be clear about what this does and does not buy. It does **not** decide
        which database is opened: a relative path resolves against the same
        working directory either way. What it buys is that the path the
        connector reports is the path it used, so "which state was I resuming
        from" has an answer that survives being pasted into an issue.

        The guard that actually prevents silent re-ingestion is tail's refusal
        to cold-start without being told
        (:class:`~ocsf_connector.runner.modes.ColdStartRefused`). Losing the
        cursor by running from another directory is only one way to lose it;
        deleting the file or restoring a stale backup look identical from here.

        ``abspath`` rather than ``resolve``: symlinks stay unfollowed on
        purpose. An operator who configures ``/var/lib/ocsf`` should see that
        path echoed back, not the ``/private/var/...`` it happens to point at on
        macOS. The goal is an answer they recognize, not a canonical one.
        """
        return Path(os.path.abspath(value.expanduser()))


class TelemetryConfig(Strict):
    enabled: bool = False
    """Off by default. The connector must never need an observability stack in
    order to run (§7)."""


class Config(Strict):
    okta: OktaConfig
    sink: SinkConfig
    # Factories, not instances: a bare ``StateConfig()`` here is built once when
    # this module is imported, which would pin the database path against
    # whatever directory the *import* happened in rather than the one the
    # configuration was loaded in. Identical in practice, wrong in principle,
    # and the kind of thing that stops being identical inside a test runner.
    state: StateConfig = Field(default_factory=StateConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
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
