"""Okta's 90-day retention, and the two ways it loses data silently (SPEC §2.6).

A query reaching past the window succeeds with only what Okta still holds, so
nothing in any response reveals the loss. Both cases are checked against the
clock instead: an opening ``since`` already past the window is refused before
anything runs, and a resumed stream whose last caught-up stamp is older than the
window is reported once and then carries on, because refusing cannot bring back
what has aged out.

All data is synthetic (CLAUDE.md invariant 5).
"""

from __future__ import annotations

import asyncio
import itertools
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import ocsf_connector.cli as cli_module
import ocsf_connector.runner.modes as modes_module
from ocsf_connector.cli import main
from ocsf_connector.config import load_config
from ocsf_connector.runner.loop import RunStats, run
from ocsf_connector.runner.modes import TAIL_STREAM, OpeningBoundRefused
from ocsf_connector.sources.base import Page
from ocsf_connector.sources.okta.source import RETENTION_SECONDS, retention_shortfall
from ocsf_connector.state.memory import InMemoryStateStore
from ocsf_connector.state.sqlite import SqliteStateStore
from tests.doubles import CaughtUpCounting, CountingMapper, RecordingSink, ScriptedSource, record
from tests.test_cli import config_with_keys

DAY = 86_400
STREAM = "okta-system-log"

# Ninety days after the bound the CLI test configs use, to the second: Sep 1 to
# Nov 30 is 29 + 31 + 30 days. Read from a calendar, not multiplied out.
SINCE = "2026-09-01T00:00:00Z"
EDGE = datetime(2026, 11, 30, tzinfo=UTC).timestamp()


# --- the vendor fact ----------------------------------------------------------


def test_the_window_is_ninety_days() -> None:
    """Pinned literally. Every other test here measures from the constant, so a
    wrong constant would move expectation and behavior together (§2.6)."""
    assert RETENTION_SECONDS == 7_776_000


def test_a_bound_inside_the_window_loses_nothing() -> None:
    assert retention_shortfall(SINCE, EDGE) == 0
    assert retention_shortfall(SINCE, EDGE - DAY) == 0


def test_a_bound_past_the_window_reports_how_far() -> None:
    assert retention_shortfall(SINCE, EDGE + 1) == 1
    assert retention_shortfall(SINCE, EDGE + DAY) == DAY


@pytest.fixture
def far_from_utc(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A bare datetime's ``timestamp()`` reads it as local time. On a machine
    already on UTC -- every CI runner -- that hides a missing conversion
    entirely, so the zone is pinned to one far from it, and put back after."""
    monkeypatch.setenv("TZ", "Pacific/Auckland")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.mark.usefixtures("far_from_utc")
def test_an_offset_is_honoured_and_a_bare_bound_is_read_as_utc() -> None:
    assert retention_shortfall("2026-09-01T00:00:00", EDGE + 1) == 1
    # Midnight at +02:00 is 22:00 the previous day in UTC: two hours further back.
    assert retention_shortfall("2026-09-01T00:00:00+02:00", EDGE) == 7_200


def test_an_unreadable_bound_is_an_error_not_a_pass() -> None:
    """Skipping the check for a bound it cannot read would put the silent case
    straight back."""
    with pytest.raises(ValueError):
        retention_shortfall("last tuesday", EDGE)


# --- the runner stamps an idle stream -----------------------------------------


def idle_source() -> ScriptedSource:
    """A caught-up polling query: an empty page whose next link is itself."""
    return ScriptedSource({"c0": Page(records=[], next_cursor="c0")})


async def test_an_idle_stream_is_stamped_at_once_then_paced() -> None:
    """The first idle page after a start proves the stream current, so it is
    stamped immediately; after that, at most once per interval. The clock
    advances a thousand seconds per reading and the interval is 4000, so pages
    at 1000 and 5000 stamp and the three between do not -- the second landing
    exactly on the interval, so "at least" and "more than" differ here."""
    store = CaughtUpCounting(InMemoryStateStore())
    ticks = itertools.count(0, 1000)
    source = idle_source()

    await run(
        source=source,
        mapper=CountingMapper(),
        # As the real sink behaves with nothing buffered. The double's default
        # flushes every page, and every flush commits and restarts the pacing.
        sink=RecordingSink(flush_every_page=False),
        store=store,
        stream=STREAM,
        start=lambda: source.start_tail(SINCE),
        max_pages=5,
        clock=lambda: float(next(ticks)),
        caught_up_every_seconds=4000,
    )

    assert store.marks == 2


def stream_then_idle() -> ScriptedSource:
    return ScriptedSource(
        {
            "c0": Page(records=[record("a1")], next_cursor="c1"),
            "c1": Page(records=[], next_cursor="c1"),
        }
    )


async def test_an_empty_page_with_events_still_buffered_is_not_caught_up() -> None:
    """Buffered means not delivered: the committed cursor sits behind events
    that only exist in memory, so the empty page proves nothing about it."""
    store = CaughtUpCounting(InMemoryStateStore())
    source = stream_then_idle()

    await run(
        source=source,
        mapper=CountingMapper(),
        sink=RecordingSink(flush_every_page=False),
        store=store,
        stream=STREAM,
        start=lambda: source.start_tail(SINCE),
        max_pages=3,
        caught_up_every_seconds=0,
    )

    assert store.marks == 0


async def test_once_delivered_the_same_empty_pages_do_stamp() -> None:
    """The contrast case for the one above: identical pages, flushed, so the
    only thing that changed is whether anything was left in the buffer."""
    store = CaughtUpCounting(InMemoryStateStore())
    source = stream_then_idle()

    await run(
        source=source,
        mapper=CountingMapper(),
        sink=RecordingSink(flush_every_page=True),
        store=store,
        stream=STREAM,
        start=lambda: source.start_tail(SINCE),
        max_pages=3,
        caught_up_every_seconds=0,
    )

    assert store.marks == 2


async def test_a_commit_restarts_the_pacing() -> None:
    """A commit stamps the stream itself, so the idle page right after it has
    nothing new to say. With the interval longer than the run, only the commit
    stamps."""
    store = CaughtUpCounting(InMemoryStateStore())
    source = stream_then_idle()

    await run(
        source=source,
        mapper=CountingMapper(),
        sink=RecordingSink(flush_every_page=True),
        store=store,
        stream=STREAM,
        start=lambda: source.start_tail(SINCE),
        max_pages=3,
        clock=lambda: 0.0,
        caught_up_every_seconds=3600,
    )

    assert store.marks == 0
    assert await store.inner.caught_up_age(STREAM) is not None, "the commit stamped it"


# --- an opening bound past the window is refused -------------------------------


def refuse_to_assemble(monkeypatch: pytest.MonkeyPatch) -> None:
    def assemble(*args: Any) -> Any:
        raise AssertionError("refused bounds must be caught before anything is opened")

    monkeypatch.setattr(modes_module, "assemble", assemble)


async def test_backfill_refuses_a_since_okta_no_longer_holds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = load_config(config_with_keys(tmp_path), env={})
    refuse_to_assemble(monkeypatch)

    with pytest.raises(OpeningBoundRefused, match=r"SPEC §2\.6") as refused:
        await modes_module.backfill(
            config, since=SINCE, until="2026-09-10T00:00:00Z", clock=lambda: EDGE + DAY
        )

    assert "2026-09-02T00:00:00Z" in str(refused.value), "names where the data starts"


async def test_backfill_refuses_a_since_it_cannot_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = load_config(config_with_keys(tmp_path), env={})
    refuse_to_assemble(monkeypatch)

    with pytest.raises(OpeningBoundRefused, match="ISO 8601"):
        await modes_module.backfill(config, since="yesterday", until="today", clock=lambda: EDGE)


async def test_backfill_inside_the_window_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = load_config(config_with_keys(tmp_path), env={})

    async def fake_run(**kwargs: Any) -> RunStats:
        return RunStats(pages=1, exhausted=True)

    monkeypatch.setattr(modes_module, "run", fake_run)

    stats = await modes_module.backfill(
        config, since=SINCE, until="2026-09-02T00:00:00Z", clock=lambda: EDGE
    )

    assert stats.exhausted


async def test_a_from_scratch_tail_refuses_an_expired_since(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = load_config(config_with_keys(tmp_path), env={})

    async def fake_run(**kwargs: Any) -> RunStats:
        raise AssertionError("must not open the stream")

    monkeypatch.setattr(modes_module, "run", fake_run)

    with pytest.raises(OpeningBoundRefused):
        await modes_module.tail(config, from_scratch=True, clock=lambda: EDGE + DAY)


def seed(path: Path, *, stamped_ago: float) -> None:
    async def commit() -> None:
        store = SqliteStateStore(path, clock=lambda: time.time() - stamped_ago)
        try:
            await store.commit(TAIL_STREAM, "c1", [], "okta-test")
        finally:
            store.close()

    asyncio.run(commit())


def test_a_resumed_tail_never_checks_its_since(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a cursor, since is never read. A tail that has simply run for
    ninety days must not start refusing its own configuration."""
    config = load_config(config_with_keys(tmp_path), env={})
    seed(tmp_path / "state.db", stamped_ago=0)

    async def fake_run(**kwargs: Any) -> RunStats:
        return RunStats(pages=1)

    monkeypatch.setattr(modes_module, "run", fake_run)

    stats = asyncio.run(modes_module.tail(config, clock=lambda: EDGE + 365 * DAY))

    assert stats.pages == 1


# --- a resumed stream older than the window is reported, then resumes ----------


def resume(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stamped_ago: float) -> list[str]:
    config = load_config(config_with_keys(tmp_path), env={})
    seed(tmp_path / "state.db", stamped_ago=stamped_ago)
    ran: list[bool] = []

    async def fake_run(**kwargs: Any) -> RunStats:
        ran.append(True)
        return RunStats(pages=1)

    monkeypatch.setattr(modes_module, "run", fake_run)
    warnings: list[str] = []

    asyncio.run(modes_module.tail(config, on_warning=warnings.append))

    assert ran, "a gap already lost is reported, never a reason to stop delivering"
    return warnings


def test_a_stream_stopped_past_the_window_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (warning,) = resume(tmp_path, monkeypatch, stamped_ago=91 * DAY)

    assert TAIL_STREAM in warning
    assert "91.0 days ago" in warning
    assert "first 1.0 days" in warning, "how much is gone, not merely that something is"


def test_a_stream_stopped_inside_the_window_says_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert resume(tmp_path, monkeypatch, stamped_ago=89 * DAY) == []


# --- what an operator sees -----------------------------------------------------


def test_the_cli_refuses_an_expired_backfill_with_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """On the real clock, which is safe here: a bound in 2020 only gets older."""
    code = main(
        [
            "--config",
            str(config_with_keys(tmp_path)),
            "backfill",
            "--since",
            "2020-01-01T00:00:00Z",
            "--until",
            "2020-01-02T00:00:00Z",
        ]
    )

    err = capsys.readouterr().err
    assert code == 2
    assert "refusing to start" in err
    assert "configuration error" not in err, "it may be an argument, not the file"


def test_the_cli_prints_a_retention_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def fake_tail(config: object, *, on_warning: Any = None, **rest: Any) -> RunStats:
        on_warning("synthetic gap")
        return RunStats(pages=1)

    monkeypatch.setattr(cli_module, "tail", fake_tail)

    assert main(["--config", str(config_with_keys(tmp_path)), "tail"]) == 0
    assert "warning: synthetic gap" in capsys.readouterr().err
