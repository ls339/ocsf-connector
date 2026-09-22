"""The command line: ``ocsf-connector tail`` and ``ocsf-connector backfill``.

Subcommands rather than a mode flag, because the two modes do not take the same
arguments and the difference is a correctness rule, not a preference: backfill's
bounds are required, and tail must not accept a ``--since`` at all. Tail's
opening bound comes from configuration (docs/SPEC.md §5.2), and a flag would
invite exactly the ``--since $(date)`` that rule exists to prevent. A parser can
refuse that; a runtime check only complains afterwards.
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from pydantic import ValidationError

from ocsf_connector.config import Config, MissingConfig, load_config
from ocsf_connector.runner.loop import RunStats
from ocsf_connector.runner.modes import ColdStartRefused, backfill, tail

DEFAULT_CONFIG = Path("config.toml")

LIVENESS_SECONDS = 300.0
"""How often a run says it is still there.

Long enough that a tail polling every ten seconds prints a line an hour rather
than a page of them, short enough to be missed by an operator watching a
terminal. Fixed rather than configurable: the number below which an alert fires
belongs to whatever is watching, not to the connector.
"""


def summarise(stats: RunStats) -> str:
    """What the run actually did, in one line.

    A successful run used to print nothing at all, which makes "fetched four
    hundred events" and "authenticated against an empty org" look identical from
    the outside. The runner already counts all of this; it was simply discarded.
    """
    parts = [
        f"{stats.pages} pages",
        f"{stats.written} events written",
        f"{stats.duplicates_skipped} duplicates skipped",
        f"{stats.commits} commits",
    ]
    if stats.exhausted:
        parts.append("range complete")
    if stats.stopped_by is not None:
        # Named rather than numbered: "stopped on SIGTERM" says a supervisor
        # asked, where "143" makes the reader look it up.
        parts.append(f"stopped on {signal.Signals(stats.stopped_by).name}")
    return ", ".join(parts)


def liveness(
    *,
    every_seconds: float = LIVENESS_SECONDS,
    clock: Callable[[], float] = time.monotonic,
    out: TextIO | None = None,
) -> Callable[[RunStats], None]:
    """A progress reporter that speaks at most once per ``every_seconds``.

    A tail prints one line at startup and then, having nothing to report until
    it stops, says nothing for as long as it runs -- so healthy-and-idle and
    wedged look identical from outside, and the run summary cannot help because
    it only exists once the run is over. SPEC §7 records why nothing already
    emitted covers this: an idle tail commits nothing, so the stored cursor's
    age and the commit lag both stand still while the poll loop is perfectly
    healthy. The signal has to come from the loop itself.

    The throttle lives here rather than in the runner because it is a question
    about how much an operator wants to read, not about how the loop works. On
    a monotonic clock, so a machine that steps its wall clock does not produce
    an hour of silence or a burst of lines.
    """
    last = clock()

    def report(stats: RunStats) -> None:
        nonlocal last
        now = clock()
        if now - last < every_seconds:
            return
        last = now
        # Resolved per line rather than defaulted in the signature: a default
        # argument binds `sys.stderr` at import, so anything that replaces the
        # stream afterwards -- a supervisor wrapping the process, a test -- goes
        # on writing to the handle this module saw first.
        print(f"alive: {summarise(stats)}", file=sys.stderr if out is None else out)

    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ocsf-connector",
        description="Ship Okta System Log events into Amazon Security Lake as OCSF Parquet.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help=f"path to the TOML configuration (default: {DEFAULT_CONFIG})",
    )
    modes = parser.add_subparsers(dest="command", required=True)

    following = modes.add_parser(
        "tail",
        help="follow the stream forever, resuming from the committed cursor",
        description=(
            "Follows Okta's polling query and never exits on its own. The opening "
            "bound comes from the configuration file, deliberately: computing it "
            "at startup breaks replay after a crash before the first commit."
        ),
    )
    # Not the camel's nose for --since. This flag cannot choose a bound; it only
    # admits that there is no cursor to resume from, and the bound it then opens
    # at still comes from configuration. The rule in this module's docstring is
    # intact.
    following.add_argument(
        "--from-scratch",
        action="store_true",
        help=(
            "start from okta.since because there is genuinely nothing to resume. "
            "Required on a first run; refuse to use it to paper over a state "
            "database the connector cannot find"
        ),
    )

    bounded = modes.add_parser(
        "backfill",
        help="walk a closed time range once, then exit",
        description=(
            "Walks a bounded query and stops when Okta stops offering a next link. "
            "Safe to run alongside a tail: they use different stream names, and the "
            "dedup set is shared, so the overlap does not duplicate events."
        ),
    )
    bounded.add_argument("--since", required=True, help="ISO 8601 lower bound, inclusive")
    bounded.add_argument("--until", required=True, help="ISO 8601 upper bound")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config: Config = load_config(args.config)
    except FileNotFoundError:
        print(f"no configuration at {args.config}", file=sys.stderr)
        return 2
    except (OSError, ValidationError, ValueError) as exc:
        print(f"configuration error in {args.config}: {exc}", file=sys.stderr)
        return 2

    # Status goes to stderr so stdout stays free for machine-readable output
    # later, and so a shell redirect of results does not swallow the one line
    # that says whether anything happened.
    destination = f"{config.okta.org_url} -> {config.sink.directory}"
    # Which state database is in use decides whether a run resumes or starts
    # over, and it was previously unanswerable from the outside. The path is
    # absolute by the time it gets here (config.StateConfig).
    print(f"state: {config.state.database}", file=sys.stderr)
    progress = liveness(every_seconds=LIVENESS_SECONDS)
    try:
        if args.command == "tail":
            print(f"tailing {destination} (Ctrl-C or SIGTERM to stop)", file=sys.stderr)
            stats = asyncio.run(tail(config, from_scratch=args.from_scratch, on_progress=progress))
        else:
            print(f"backfilling {args.since} .. {args.until} {destination}", file=sys.stderr)
            stats = asyncio.run(
                backfill(config, since=args.since, until=args.until, on_progress=progress)
            )
    except MissingConfig as exc:
        # A setting this mode needs, not a runtime failure -- so it exits 2 with
        # the other configuration problems rather than 1.
        print(f"configuration error in {args.config}: {exc}", file=sys.stderr)
        return 2
    except ColdStartRefused as exc:
        # Deliberately not borrowing the "configuration error" wording: the file
        # is fine, the state is not, and sending an operator to edit the config
        # would be sending them to the wrong place. Still exit 2 -- nothing ran,
        # and something has to be fixed before anything will.
        print(f"refusing to start: {exc}", file=sys.stderr)
        return 2
    except (KeyboardInterrupt, asyncio.CancelledError):
        # No longer the ordinary way a run ends: a signal is handled inside the
        # loop now and comes back as `stopped_by`. What is left here is a signal
        # arriving outside that window -- during startup or teardown -- and the
        # second one, which cancels rather than waiting for the page in flight.
        # Either way the cursor is committed only after an acknowledged batch,
        # so stopping here loses nothing (§5).
        print("interrupted", file=sys.stderr)
        return 130

    print(summarise(stats), file=sys.stderr)
    if stats.stopped_by is not None:
        # The shell convention, and what a supervisor reads to tell "asked to
        # stop" from "fell over": 130 for SIGINT, 143 for SIGTERM.
        return 128 + stats.stopped_by
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
