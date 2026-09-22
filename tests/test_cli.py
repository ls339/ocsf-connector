"""The command line, and the composition root behind it.

Most of this file is about what the parser refuses. `tail` must not accept a
`--since`, because the whole point of docs/SPEC.md §5.2 is that the opening bound
cannot be computed per invocation -- and `--since $(date)` is precisely how
someone would compute it. Refusing the flag is cheaper than explaining the bug.

Synthetic throughout (CLAUDE.md invariant 5).
"""

from __future__ import annotations

import asyncio
import io
import signal
from pathlib import Path
from typing import Any

import httpx
import pytest

import ocsf_connector.cli as cli_module
import ocsf_connector.runner.modes as modes_module
from ocsf_connector.cli import build_parser, liveness, main, summarise
from ocsf_connector.config import load_config
from ocsf_connector.runner.loop import RunStats
from ocsf_connector.runner.modes import BACKFILL_STREAM, TAIL_STREAM, assemble
from ocsf_connector.sources.okta.auth import BearerAuth, DpopAuth
from ocsf_connector.state.sqlite import SqliteStateStore
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
    # Point the store at tmp_path. The default is a *relative* path, so without
    # this the suite opens state/ocsf-connector.db in whatever directory pytest
    # was run from -- writing a database into the working tree, which a test has
    # no business doing.
    body += f'\n[state]\ndatabase = "{tmp_path / "state.db"}"\n'
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
    broken = write(tmp_path, MINIMAL + "\nnot_a_real_setting = 1\n")

    code = main(["--config", str(broken), "tail"])

    assert code == 2
    assert "configuration error" in capsys.readouterr().err


def test_tail_refuses_to_start_without_an_opening_bound(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """§5.2's obligation, enforced at the mode entry point: the connector would
    rather refuse to start than invent a bound that moves between restarts."""
    without = config_with_keys(tmp_path, MINIMAL.replace('since = "2026-09-01T00:00:00Z"\n', ""))

    code = main(["--config", str(without), "tail"])

    err = capsys.readouterr().err
    assert code == 2, "a missing setting is a configuration error, not a runtime failure"
    assert "okta.since" in err
    assert "§5.2" in err, "and says why, so nobody 'fixes' it with a default"


def test_backfill_needs_no_configured_since(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of making it optional: backfill takes its bounds as arguments,
    so a backfill-only deployment should not have to supply a field nothing
    reads."""
    without = config_with_keys(tmp_path, MINIMAL.replace('since = "2026-09-01T00:00:00Z"\n', ""))
    seen: dict[str, str] = {}

    async def fake_backfill(config: object, *, since: str, until: str, **rest: Any) -> RunStats:
        seen.update(since=since, until=until)
        return RunStats(pages=1, exhausted=True)

    monkeypatch.setattr(cli_module, "backfill", fake_backfill)

    code = main(
        [
            "--config",
            str(without),
            "backfill",
            "--since",
            "2026-09-01T00:00:00Z",
            "--until",
            "2026-09-02T00:00:00Z",
        ]
    )

    assert code == 0
    assert seen == {"since": "2026-09-01T00:00:00Z", "until": "2026-09-02T00:00:00Z"}


# --- what a run tells the operator ------------------------------------------


def test_the_summary_reports_what_the_run_did() -> None:
    """Silence made "fetched four hundred events" and "authenticated against an
    empty org" indistinguishable from outside."""
    line = summarise(RunStats(pages=3, mapped=12, written=10, duplicates_skipped=2, commits=3))

    assert "3 pages" in line
    assert "10 events written" in line
    assert "2 duplicates skipped" in line
    assert "range complete" not in line, "a tail that stopped has not finished a range"


def test_a_finished_range_says_so() -> None:
    assert "range complete" in summarise(RunStats(pages=1, exhausted=True))


def test_a_completed_run_prints_its_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path = config_with_keys(tmp_path)

    async def fake_backfill(config: object, *, since: str, until: str, **rest: Any) -> RunStats:
        return RunStats(pages=2, mapped=5, written=5, commits=2, exhausted=True)

    monkeypatch.setattr(cli_module, "backfill", fake_backfill)

    code = main(
        [
            "--config",
            str(config_path),
            "backfill",
            "--since",
            "2026-09-01T00:00:00Z",
            "--until",
            "2026-09-02T00:00:00Z",
        ]
    )

    assert code == 0
    err = capsys.readouterr().err
    assert "backfilling" in err, "and says what it is about to do before it does it"
    assert "5 events written" in err
    assert "range complete" in err


def test_a_stopped_run_reports_what_it_did_and_which_signal_stopped_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The bug: tail's only exit was an interrupt raised through whatever await
    was running, so the mode that runs long enough to need a summary was the one
    mode that could never print one. It now returns its stats instead."""

    async def stopped(config: object, *, from_scratch: bool = False, **rest: Any) -> RunStats:
        return RunStats(pages=97, mapped=40, written=38, commits=6, stopped_by=signal.SIGTERM)

    monkeypatch.setattr(cli_module, "tail", stopped)

    code = main(["--config", str(config_with_keys(tmp_path)), "tail"])

    err = capsys.readouterr().err
    assert code == 143, "128+SIGTERM: a supervisor asked, and nothing fell over"
    assert "97 pages" in err and "38 events written" in err
    assert "stopped on SIGTERM" in err


def test_a_tail_stopped_by_ctrl_c_exits_130(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Which signal stopped it survives to the exit code, because that is the
    difference between a deploy and an outage on whatever is watching."""

    async def stopped(config: object, *, from_scratch: bool = False, **rest: Any) -> RunStats:
        return RunStats(pages=4, stopped_by=signal.SIGINT)

    monkeypatch.setattr(cli_module, "tail", stopped)

    assert main(["--config", str(config_with_keys(tmp_path)), "tail"]) == 130
    assert "stopped on SIGINT" in capsys.readouterr().err


def test_a_run_that_was_not_stopped_says_nothing_about_signals() -> None:
    assert "stopped on" not in summarise(RunStats(pages=2, exhausted=True))


def test_stopping_a_tail_is_not_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The escape hatch, not the ordinary path any more: a signal arriving
    outside the window the handler covers, or a second one, which cancels rather
    than waiting for the page in flight. The cursor is committed after every
    acknowledged batch, so nothing is lost either way (§5)."""

    async def interrupted(config: object, *, from_scratch: bool = False, **rest: Any) -> RunStats:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_module, "tail", interrupted)

    code = main(["--config", str(config_with_keys(tmp_path)), "tail"])

    assert code == 130
    assert "interrupted" in capsys.readouterr().err


# --- saying it is alive ------------------------------------------------------


def test_the_liveness_line_is_throttled_to_one_per_interval() -> None:
    """A tail polling every ten seconds would otherwise print six lines a
    minute, which is how an operator learns to pipe the thing to /dev/null."""
    ticks = iter([0.0, 10.0, 20.0, 61.0, 70.0, 130.0])
    out = io.StringIO()
    report = liveness(every_seconds=60.0, clock=lambda: next(ticks), out=out)

    for pages in (1, 2, 3, 4, 5):
        report(RunStats(pages=pages))

    assert out.getvalue().splitlines() == [
        "alive: 3 pages, 0 events written, 0 duplicates skipped, 0 commits",
        "alive: 5 pages, 0 events written, 0 duplicates skipped, 0 commits",
    ]


def test_the_liveness_line_says_the_run_is_still_polling() -> None:
    """Pages climbing with nothing written is the healthy idle tail §7
    describes: it commits nothing, so nothing else it emits moves."""
    out = io.StringIO()
    report = liveness(every_seconds=0.0, clock=lambda: 0.0, out=out)

    report(RunStats(pages=42, written=0, commits=0))

    assert out.getvalue().startswith("alive: 42 pages")


def test_a_tail_is_handed_the_liveness_reporter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The wire, not the pieces. Both ends are tested above -- the runner reports
    every page, the throttle prints at most one line per interval -- and a tail
    that was never handed a reporter would still pass both of them and go silent
    for as long as it ran, which is the bug.

    The interval is turned off here because the point is the connection, not the
    pacing; left at five minutes this would assert nothing for five minutes.
    """
    monkeypatch.setattr(cli_module, "LIVENESS_SECONDS", 0.0)

    async def fake_tail(
        config: object, *, from_scratch: bool = False, on_progress: Any = None, **rest: Any
    ) -> RunStats:
        assert on_progress is not None, "a tail with no reporter says nothing until it dies"
        on_progress(RunStats(pages=11, written=4, commits=2))
        return RunStats(pages=11, written=4, commits=2, stopped_by=signal.SIGINT)

    monkeypatch.setattr(cli_module, "tail", fake_tail)

    main(["--config", str(config_with_keys(tmp_path)), "tail"])

    assert "alive: 11 pages, 4 events written" in capsys.readouterr().err


def test_a_backfill_is_handed_one_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A backfill of a long range is just as quiet, and just as long."""
    monkeypatch.setattr(cli_module, "LIVENESS_SECONDS", 0.0)

    async def fake_backfill(
        config: object, *, since: str, until: str, on_progress: Any = None, **rest: Any
    ) -> RunStats:
        assert on_progress is not None
        on_progress(RunStats(pages=7, written=700))
        return RunStats(pages=7, written=700, exhausted=True)

    monkeypatch.setattr(cli_module, "backfill", fake_backfill)

    main(
        [
            "--config",
            str(config_with_keys(tmp_path)),
            "backfill",
            "--since",
            "2026-09-01T00:00:00Z",
            "--until",
            "2026-09-02T00:00:00Z",
        ]
    )

    assert "alive: 7 pages, 700 events written" in capsys.readouterr().err


# --- refusing to start on state that is not there ----------------------------


def test_tail_accepts_a_from_scratch_flag() -> None:
    """Not a `--since` in disguise: it cannot choose a bound, only admit that
    there is no cursor. The bound still comes from configuration."""
    args = build_parser().parse_args(["tail", "--from-scratch"])

    assert args.from_scratch is True
    assert not hasattr(args, "since"), "tail still takes no time bounds (§5.2)"


def test_tail_does_not_mistake_lost_state_for_a_first_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An empty database and a genuine first run look identical from inside.

    Nothing below can tell them apart either: assemble() creates the state
    directory wherever the process was launched, and SQLite creates the file on
    connect, so neither layer can raise. Left alone the runner would open from
    okta.since and re-ingest everything since that bound in silence.
    """
    code = main(["--config", str(config_with_keys(tmp_path)), "tail"])

    err = capsys.readouterr().err
    assert code == 2
    assert "--from-scratch" in err, "and says how to proceed if it really is the first run"
    assert "configuration error" not in err, (
        "the config file is fine and the state is not -- saying otherwise sends "
        "an operator to edit the wrong thing"
    )


def test_from_scratch_lets_a_genuine_first_run_proceed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def fake_run(**kwargs: Any) -> RunStats:
        return RunStats(pages=1, written=3)

    monkeypatch.setattr(modes_module, "run", fake_run)

    code = main(["--config", str(config_with_keys(tmp_path)), "tail", "--from-scratch"])

    assert code == 0
    assert "3 events written" in capsys.readouterr().err


def test_tail_resumes_without_the_flag_once_a_cursor_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The flag is for the first run, not something to type forever. A steady
    state that needed it would train operators to pass it always, which would
    put the silent re-ingestion right back."""
    config_path = config_with_keys(tmp_path)

    async def seed() -> None:
        store = SqliteStateStore(tmp_path / "state.db")
        try:
            await store.commit(TAIL_STREAM, "c1", [], "okta-test")
        finally:
            store.close()

    asyncio.run(seed())

    async def fake_run(**kwargs: Any) -> RunStats:
        return RunStats(pages=1, written=1)

    monkeypatch.setattr(modes_module, "run", fake_run)

    assert main(["--config", str(config_path), "tail"]) == 0


def test_the_run_says_which_state_database_it_is_using(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Which database is in use decides whether a run resumes or starts over,
    and it used to be unanswerable from outside -- which is how the working
    directory got to decide it unnoticed."""

    async def fake_backfill(config: object, *, since: str, until: str, **rest: Any) -> RunStats:
        return RunStats(pages=1, exhausted=True)

    monkeypatch.setattr(cli_module, "backfill", fake_backfill)

    main(
        [
            "--config",
            str(config_with_keys(tmp_path)),
            "backfill",
            "--since",
            "2026-09-01T00:00:00Z",
            "--until",
            "2026-09-02T00:00:00Z",
        ]
    )

    assert f"state: {tmp_path / 'state.db'}" in capsys.readouterr().err


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
