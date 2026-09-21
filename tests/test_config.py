"""Configuration loading.

The interesting assertions here are about what the loader *refuses*: a missing
`since`, an unknown key, an out-of-range page size. A config loader that accepts
anything turns an operator's typo into a connector that runs and quietly does
something else.

Synthetic throughout (CLAUDE.md invariant 5).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from ocsf_connector.config import ENV_OVERRIDES, load_config

MINIMAL = """
[okta]
org_url = "https://synthetic.okta.example"
client_id = "0oasynthetic0000001"
kid = "synthetic-key-1"
private_key_file = "/run/secrets/key.pem"
since = "2026-09-01T00:00:00Z"

[sink]
region = "us-east-1"
account_id = "external_synthetic-org"
"""


def write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(body)
    return path


def test_a_minimal_file_loads_with_sensible_defaults(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, MINIMAL), env={})

    assert config.okta.org_url == "https://synthetic.okta.example"
    assert config.okta.since == "2026-09-01T00:00:00Z"
    assert config.okta.limit == 1000, "Okta's ceiling, and the throughput ceiling (§2.3)"
    assert config.okta.dpop_key_file is None, "DPoP is opt-in by naming its key"
    assert config.sink.kind == "local"
    assert config.state.database == Path("state/ocsf-connector.db").absolute(), (
        "the default is still relative in the file, but absolute by the time anything reads it"
    )
    assert config.telemetry.enabled is False, "no observability stack required to run (§7)"
    assert config.stream is None, "so each mode uses its own default"


def test_since_may_be_absent_but_is_never_defaulted(tmp_path: Path) -> None:
    """docs/SPEC.md §5.2: the opening cursor must be stable across a restart, so
    it comes from configuration and never from now().

    What enforces that is the absence of a *default*, not the field being
    mandatory -- a plausible-looking `now() - 1 hour` would reintroduce the
    duplicate object in silence. So a backfill-only config may omit it, and what
    it gets is None, which nothing can mistake for a bound. Tail refuses to
    start on it (see tests/test_cli.py).
    """
    without = MINIMAL.replace('since = "2026-09-01T00:00:00Z"\n', "")

    config = load_config(write(tmp_path, without), env={})

    assert config.okta.since is None, "absent, rather than quietly invented"


def test_an_unknown_key_is_refused(tmp_path: Path) -> None:
    """A typo is otherwise a setting that silently does nothing."""
    with pytest.raises(ValidationError, match=r"pol_seconds|extra"):
        load_config(write(tmp_path, MINIMAL + "\npol_seconds = 5\n"), env={})


@pytest.mark.parametrize("limit", [0, 1001])
def test_a_page_size_okta_will_not_accept_is_refused(tmp_path: Path, limit: int) -> None:
    body = MINIMAL.replace('since = "', f'limit = {limit}\nsince = "')

    with pytest.raises(ValidationError, match="limit"):
        load_config(write(tmp_path, body), env={})


def test_the_environment_overrides_the_file(tmp_path: Path) -> None:
    """So a container can carry the boring settings in an image and the
    deployment-specific ones in its environment."""
    config = load_config(
        write(tmp_path, MINIMAL),
        env={
            "OCSF_OKTA_CLIENT_ID": "0oafrom-the-environment",
            "OCSF_SINK_REGION": "eu-west-1",
            "OCSF_STREAM": "okta-tail-blue",
        },
    )

    assert config.okta.client_id == "0oafrom-the-environment"
    assert config.sink.region == "eu-west-1"
    assert config.stream == "okta-tail-blue"
    assert config.okta.org_url == "https://synthetic.okta.example", "the rest is untouched"


def test_a_boolean_override_is_not_merely_a_non_empty_string(tmp_path: Path) -> None:
    """ "false" is true in every language that tests strings for truthiness, and
    a telemetry flag that cannot be turned off from the environment is a trap."""
    enabled = load_config(write(tmp_path, MINIMAL), env={"OCSF_TELEMETRY_ENABLED": "true"})
    disabled = load_config(write(tmp_path, MINIMAL), env={"OCSF_TELEMETRY_ENABLED": "false"})

    assert enabled.telemetry.enabled is True
    assert disabled.telemetry.enabled is False


def test_an_override_can_create_a_section_the_file_omits(tmp_path: Path) -> None:
    config = load_config(
        write(tmp_path, MINIMAL), env={"OCSF_STATE_DATABASE": "/var/lib/ocsf/state.db"}
    )

    assert config.state.database == Path("/var/lib/ocsf/state.db")


def test_a_relative_database_path_is_pinned_at_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Which database is opened decides whether a run resumes or starts over, and
    a relative path makes the working directory the thing that decides.

    Pinning it does not change *which* file is opened -- it resolves against the
    same directory either way. What it buys is that the path the connector
    reports is the path it used. The guard that actually prevents silent
    re-ingestion is tail's refusal to cold-start (tests/test_cli.py).
    """
    monkeypatch.chdir(tmp_path)
    body = MINIMAL + '\n[state]\ndatabase = "state/ocsf-connector.db"\n'

    config = load_config(write(tmp_path, body), env={})

    # Against cwd rather than tmp_path: abspath resolves through os.getcwd(),
    # which macOS reports symlink-free, so tmp_path itself may not compare equal.
    assert config.state.database.is_absolute()
    assert config.state.database == Path.cwd() / "state" / "ocsf-connector.db"


def test_the_default_is_built_at_load_not_at_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file with no [state] section still pins against the loading directory.

    This is the only place the distinction shows. A bare ``StateConfig()`` as
    the field default is constructed once, when the module is imported, so its
    path would pin against whatever directory the interpreter started in --
    which under a service manager or a test runner is not the directory the
    operator ran from. Every other test here happens to import and load from the
    same place, so none of them can tell the two apart.
    """
    monkeypatch.chdir(tmp_path)

    config = load_config(write(tmp_path, MINIMAL), env={})

    assert config.state.database == Path.cwd() / "state" / "ocsf-connector.db"


def test_pinning_does_not_rewrite_the_path_an_operator_wrote(tmp_path: Path) -> None:
    """abspath, not resolve. On macOS /var is a symlink to /private/var, so
    resolving would echo back a path the operator never typed and would have to
    translate before believing it."""
    config = load_config(
        write(tmp_path, MINIMAL), env={"OCSF_STATE_DATABASE": "/var/lib/ocsf/state.db"}
    )

    assert config.state.database == Path("/var/lib/ocsf/state.db")


def test_every_override_points_somewhere_real(tmp_path: Path) -> None:
    """The table is the operator-facing list of variables. An entry naming a
    field that no longer exists would be documentation that lies."""
    config = load_config(write(tmp_path, MINIMAL), env={})

    for variable, location in ENV_OVERRIDES.items():
        node: object = config
        for key in location:
            assert hasattr(node, key), f"{variable} points at a missing field: {'.'.join(location)}"
            node = getattr(node, key)


def test_a_missing_file_is_an_error_not_an_empty_config(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "absent.toml", env={})
