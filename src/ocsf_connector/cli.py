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
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from ocsf_connector.config import Config, load_config
from ocsf_connector.runner.loop import RunStats
from ocsf_connector.runner.modes import backfill, tail

DEFAULT_CONFIG = Path("config.toml")


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
    return ", ".join(parts)


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

    modes.add_parser(
        "tail",
        help="follow the stream forever, resuming from the committed cursor",
        description=(
            "Follows Okta's polling query and never exits on its own. The opening "
            "bound comes from the configuration file, deliberately: computing it "
            "at startup breaks replay after a crash before the first commit."
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
    try:
        if args.command == "tail":
            print(f"tailing {destination} (Ctrl-C to stop)", file=sys.stderr)
            stats = asyncio.run(tail(config))
        else:
            print(f"backfilling {args.since} .. {args.until} {destination}", file=sys.stderr)
            stats = asyncio.run(backfill(config, since=args.since, until=args.until))
    except KeyboardInterrupt:
        # Tail never returns on its own, so this is its normal exit. The cursor
        # is committed after every acknowledged batch, so stopping here loses
        # nothing (§5).
        print("interrupted", file=sys.stderr)
        return 130

    print(summarise(stats), file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
