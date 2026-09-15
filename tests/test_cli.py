"""The command line, and the composition root behind it.

Most of this file is about what the parser refuses. `tail` must not accept a
`--since`, because the whole point of docs/SPEC.md §5.2 is that the opening bound
cannot be computed per invocation -- and `--since $(date)` is precisely how
someone would compute it. Refusing the flag is cheaper than explaining the bug.

Synthetic throughout (CLAUDE.md invariant 5).
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from ocsf_connector.cli import build_parser, main
from ocsf_connector.config import load_config
from ocsf_connector.runner.modes import BACKFILL_STREAM, TAIL_STREAM, assemble
from ocsf_connector.sources.okta.auth import BearerAuth, DpopAuth
from ocsf_connector.telemetry.base import NullMetrics
from ocsf_connector.telemetry.otel import OtelMetrics
from tests.test_config import MINIMAL, write

# Real key material, reusing the pair that suite already generates at import
# rather than paying for a third. It has to be real: DpopAuth derives the public
# JWK for its proof header at construction, so a malformed key fails at startup
# rather than at the first token request an hour later (§2.4). BearerAuth would
# accept anything, since credentials only hold the text until they sign.
from tests.test_okta_auth import CLIENT_KEY, DPOP_KEY


def config_with_keys(tmp_path: Path, body: str = MINIMAL, *, dpop: bool = False) -> Path:
    key = tmp_path / "client.pem"
    key.write_text(CLIENT_KEY)
    body = body.replace("/run/secrets/key.pem", str(key))
    if dpop:
        dpop_key = tmp_path / "dpop.pem"
        dpop_key.write_text(DPOP_KEY)
        body = body.replace("since = ", f'dpop_key_file = "{dpop_key}"\nsince = ')
    return write(tmp_path, body)


# --- the parser -------------------------------------------------------------


def test_tail_takes_no_time_bounds() -> None:
    """§5.2: a flag here invites `--since $(date)`, which breaks replay after a
    crash before the first commit. The parser refuses rather than the runtime."""
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["tail", "--since", "2026-09-01T00:00:00Z"])


def test_backfill_requires_both_bounds() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["backfill", "--since", "2026-09-01T00:00:00Z"])


def test_backfill_accepts_a_closed_range() -> None:
    args = build_parser().parse_args(
        ["backfill", "--since", "2026-09-01T00:00:00Z", "--until", "2026-09-02T00:00:00Z"]
    )

    assert (args.command, args.since, args.until) == (
        "backfill",
        "2026-09-01T00:00:00Z",
        "2026-09-02T00:00:00Z",
    )


def test_a_mode_is_required() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_a_missing_config_exits_nonzero_without_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["--config", str(tmp_path / "absent.toml"), "tail"])

    assert code == 2
    assert "no configuration at" in capsys.readouterr().err


def test_an_invalid_config_exits_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = write(tmp_path, MINIMAL.replace('since = "2026-09-01T00:00:00Z"\n', ""))

    code = main(["--config", str(broken), "tail"])

    assert code == 2
    assert "configuration error" in capsys.readouterr().err


# --- the composition root ---------------------------------------------------


async def test_assemble_wires_the_pipeline_from_config(tmp_path: Path) -> None:
    config = load_config(config_with_keys(tmp_path), env={})

    async with httpx.AsyncClient() as client:
        parts = assemble(config, client)
        try:
            assert parts.source.org_url == "https://synthetic.okta.example"
            assert parts.source.limit == 1000
            assert isinstance(parts.source.auth, BearerAuth), "no DPoP key named"
            assert parts.sink.account_id == "external_synthetic-org"
            assert parts.sink.source_name == "okta"
            assert isinstance(parts.metrics, NullMetrics), "telemetry off by default"
            assert (tmp_path / "state").exists() or config.state.database.parent.exists()
        finally:
            parts.close()


async def test_naming_a_dpop_key_selects_dpop(tmp_path: Path) -> None:
    """§2.4: an operator says which mode the app is in by naming the second key."""
    config = load_config(config_with_keys(tmp_path, dpop=True), env={})

    async with httpx.AsyncClient() as client:
        parts = assemble(config, client)
        try:
            assert isinstance(parts.source.auth, DpopAuth)
        finally:
            parts.close()


async def test_telemetry_is_wired_only_when_enabled(tmp_path: Path) -> None:
    body = MINIMAL + "\n[telemetry]\nenabled = true\n"
    config = load_config(config_with_keys(tmp_path, body), env={})

    async with httpx.AsyncClient() as client:
        parts = assemble(config, client)
        try:
            assert isinstance(parts.metrics, OtelMetrics)
            assert parts.mapper.on_unmapped is not None, "the drift alarm is connected (§3.3)"
        finally:
            parts.close()


async def test_the_two_modes_do_not_share_a_stream_name() -> None:
    """The store is keyed by stream: sharing one would let a backfill overwrite
    the tail's cursor. The dedup set is global, so the overlap stays safe."""
    assert TAIL_STREAM != BACKFILL_STREAM


async def test_the_key_is_read_at_startup_not_held_as_a_path(tmp_path: Path) -> None:
    """A file that becomes unreadable later must not break a running connector,
    and nothing downstream should need to know where the key came from."""
    config = load_config(config_with_keys(tmp_path), env={})

    async with httpx.AsyncClient() as client:
        parts = assemble(config, client)
        try:
            (tmp_path / "client.pem").unlink()
            assert isinstance(parts.source.auth, BearerAuth)
            assert parts.source.auth.credentials.private_key == CLIENT_KEY
        finally:
            parts.close()
