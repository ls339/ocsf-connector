"""Reconcile one closed window: what Okta holds against what reached the lake.

CI never runs this: CI has no credentials and makes no live calls. It answers
the one question every test in this repository answers only by construction --
*was anything lost or written twice?* -- by measuring it against the live data.

It compares event ids, not totals. Totals can agree while one event is missing
and another is doubled, which is exactly the failure a count would hide.

1. **Okta's side.** A bounded query over ``[since, until)`` through the
   connector's own ``OktaSource``, so the answer is about the connector's
   reading of Okta, not a hand-rolled one (§2.1).
2. **The lake's side.** One Athena query per custom source table, filtered on
   OCSF ``time`` -- set from ``published``, so both sides use the same clock --
   over the window padded on both ends.
3. **The comparison.**

   ``missing``      in Okta, nowhere in the padded lake window. Data loss.
   ``extra``        in the lake inside the strict window, not in Okta.
   ``duplicated``   one id on more than one lake row in the same table: the
                    exactly-once design failed (§5.2).
   ``cross-class``  one id in two tables. Usually a stranded object left by a
                    mapping change re-run (RUNBOOK, "Re-running a backfill after
                    a mapping change"), which is known but still not clean.

   The lake is read over a padded window so that an event Okta files a few
   milliseconds differently at the edge cannot pass for a missing one; ``extra``
   is still judged on the strict window, so padding cannot hide an extra.

It prints counts, and for any mismatch the first few sha256 prefixes of the ids
involved -- never an id, a payload, a host, a table name or an account. The
output is safe to paste into an issue (CLAUDE.md invariant 6). Exit 0 when
every mismatch is zero, 1 otherwise, 2 for bad arguments.

Pick a window that is closed and settled: inside Okta's 90 days, ending some
hours ago (Okta warns bounded queries near the present may still miss delayed
events, §2.1), covered by the tail throughout, and crawled -- partitions are
invisible to Athena until the daily crawl registers them (RUNBOOK B7). A window
spanning a restart exercises the code most worth checking.

Usage::

    terraform -chdir=terraform/log-archive output -json glue_tables > /tmp/glue_tables.json
    export AWS_PROFILE=...   # an identity with a Lake Formation SELECT grant (RUNBOOK B7)
    uv run python scripts/reconcile.py --config config.toml \\
        --glue-tables /tmp/glue_tables.json \\
        --since 2026-10-15T00:00:00Z --until 2026-10-17T00:00:00Z \\
        --output-location s3://<athena-results-bucket>/reconcile/

The Okta read uses the same app as a running tail and draws on the same rate
budget; a window of a few days on a quiet org is a handful of pages.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time
import tomllib
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import boto3
import httpx

from ocsf_connector.config import ENV_OVERRIDES, OktaConfig
from ocsf_connector.sources.okta.auth import BearerAuth, DpopAuth, OktaClientCredentials
from ocsf_connector.sources.okta.source import OktaSource, retention_shortfall

SETTLE_HOURS = 6
"""How long ago the window must end. Okta's bounded queries may miss events that
are still being delayed near the present (§2.1); a few hours is ample."""

SHOWN = 5
"""Hash prefixes printed per mismatch class: enough to chase, few enough to paste."""


@dataclass(frozen=True, slots=True)
class LakeRow:
    uid: str
    time_ms: int
    source: str


@dataclass(frozen=True, slots=True)
class Result:
    okta_events: int
    okta_unique: int
    lake_rows: int
    missing: list[str]
    extra: list[str]
    duplicated: list[str]
    cross_class: list[str]
    blank_uids: int

    @property
    def clean(self) -> bool:
        return not (
            self.missing or self.extra or self.duplicated or self.cross_class or self.blank_uids
        )


def compare(okta_uids: list[str], lake: list[LakeRow], since_ms: int, until_ms: int) -> Result:
    """The whole judgement, with no I/O, so it can be checked by hand.

    ``lake`` is the padded read; only ``extra`` narrows it to the strict window.
    """
    okta = set(okta_uids)
    padded = {row.uid for row in lake}
    strict = {row.uid for row in lake if since_ms <= row.time_ms < until_ms}

    per_table = Counter((row.uid, row.source) for row in lake)
    tables_per_uid: defaultdict[str, set[str]] = defaultdict(set)
    for row in lake:
        tables_per_uid[row.uid].add(row.source)

    return Result(
        okta_events=len(okta_uids),
        okta_unique=len(okta),
        lake_rows=len(lake),
        missing=sorted(okta - padded),
        extra=sorted(strict - okta),
        duplicated=sorted({uid for (uid, _), count in per_table.items() if count > 1}),
        cross_class=sorted(uid for uid, tables in tables_per_uid.items() if len(tables) > 1),
        blank_uids=sum(1 for row in lake if not row.uid),
    )


def fingerprint(uids: Iterable[str]) -> str:
    """The first few ids as sha256 prefixes: chaseable, not publishable."""
    shown = [hashlib.sha256(uid.encode()).hexdigest()[:12] for uid in list(uids)[:SHOWN]]
    return ", ".join(shown)


# --- Okta -------------------------------------------------------------------


def read_okta_config(path: Path) -> OktaConfig:
    """Only the ``[okta]`` section, with its ``OCSF_OKTA_*`` overrides applied.

    Validating the whole file would demand settings this probe never touches: a
    config whose sink takes its external id from the deployment's environment
    fails here on a value that has nothing to do with reading Okta.
    """
    with path.open("rb") as handle:
        section: dict[str, object] = dict(tomllib.load(handle).get("okta", {}))
    for variable, location in ENV_OVERRIDES.items():
        if len(location) == 2 and location[0] == "okta" and variable in os.environ:
            section[location[1]] = os.environ[variable]
    return OktaConfig.model_validate(section)


async def read_okta(config_path: Path, since: str, until: str) -> list[str]:
    """Every uuid Okta returns for the window, repeats included.

    Built the way `runner.modes.assemble` builds the source, minus everything
    else it assembles: in particular no state store, because opening the
    connector's database from a probe is how a probe becomes a second writer.
    """
    okta = read_okta_config(config_path)
    async with httpx.AsyncClient() as client:
        credentials = OktaClientCredentials(
            org_url=okta.org_url,
            client_id=okta.client_id,
            private_key=okta.client_key(),
            kid=okta.kid,
            client=client,
        )
        proof_key = okta.proof_key()
        auth = DpopAuth(credentials, dpop_key=proof_key) if proof_key else BearerAuth(credentials)
        source = OktaSource(org_url=okta.org_url, client=client, auth=auth, limit=okta.limit)

        uids: list[str] = []
        cursor: str | None = await source.start_backfill(since, until)
        pages = 0
        while cursor is not None:
            page = await source.fetch(cursor)
            pages += 1
            uids.extend(str(record.get("uuid") or "") for record in page.records)
            cursor = page.next_cursor
        print(f"okta: {pages} pages, {len(uids)} events", file=sys.stderr)
        return uids


# --- the lake ---------------------------------------------------------------


def parse_table_arn(arn: str) -> tuple[str, str | None, str]:
    """A Glue table ARN -> region, database if it names one, table.

    Glue's own form is ``table/<database>/<table>``, but the ARN Security Lake
    reports for a custom source is ``table/<table>`` with no database at all --
    found by running this, after the first version assumed Glue's form.
    """
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[2] != "glue" or not parts[5].startswith("table/"):
        raise ValueError("not a Glue table ARN")
    path = parts[5].split("/")[1:]
    if len(path) == 2:
        return parts[3], path[0], path[1]
    if len(path) == 1 and path[0]:
        return parts[3], None, path[0]
    raise ValueError("not a Glue table ARN")


def find_database(glue: Any, table: str) -> str:
    """The one database holding ``table``, asked of Glue rather than built from
    Security Lake's naming pattern: a constructed identifier fails far from its
    cause (the verify-and-compute memory has three such cases)."""
    holders = []
    for page in glue.get_paginator("get_databases").paginate():
        for database in page["DatabaseList"]:
            try:
                glue.get_table(DatabaseName=database["Name"], Name=table)
            except glue.exceptions.EntityNotFoundException:
                continue
            holders.append(database["Name"])
    if len(holders) != 1:
        raise RuntimeError(f"expected one database holding the table, found {len(holders)}")
    return str(holders[0])


def athena_rows(
    athena: Any, sql: str, database: str, workgroup: str, output: str | None
) -> list[list[str | None]]:
    request: dict[str, Any] = {
        "QueryString": sql,
        "QueryExecutionContext": {"Database": database},
        "WorkGroup": workgroup,
    }
    if output:
        request["ResultConfiguration"] = {"OutputLocation": output}
    execution_id = athena.start_query_execution(**request)["QueryExecutionId"]

    while True:
        state = athena.get_query_execution(QueryExecutionId=execution_id)["QueryExecution"]
        status = state["Status"]["State"]
        if status == "SUCCEEDED":
            break
        if status in ("FAILED", "CANCELLED"):
            # The reason can name a table or an account; it goes to the
            # operator's terminal, which already knows both, not into a note.
            raise RuntimeError(f"athena query {status}: {state['Status'].get('StateChangeReason')}")
        time.sleep(1)

    rows: list[list[str | None]] = []
    for page in athena.get_paginator("get_query_results").paginate(QueryExecutionId=execution_id):
        for row in page["ResultSet"]["Rows"]:
            rows.append([cell.get("VarCharValue") for cell in row["Data"]])
    return rows[1:]  # the first row is the header


def read_lake(
    tables: dict[str, str],
    since_ms: int,
    until_ms: int,
    pad: timedelta,
    workgroup: str,
    output: str | None,
) -> tuple[list[LakeRow], int, list[str]]:
    """Rows in the padded window from every source table; how many sit in the
    epoch partition -- events whose timestamp did not parse, which are delivered
    but outside any window, and would otherwise read as missing; and which
    tables had no schema to query.

    A table with no columns has never been crawled with data in it (RUNBOOK
    B7), and Athena refuses any query naming a column on it. Skipping one is
    safe rather than convenient: if Okta holds events of that class in the
    window, they surface as ``missing``, which is the alarm that matters.
    """
    low = since_ms - int(pad.total_seconds() * 1000)
    high = until_ms + int(pad.total_seconds() * 1000)
    day_low, day_high = _event_day(low), _event_day(high)

    rows: list[LakeRow] = []
    undated = 0
    schemaless: list[str] = []
    for source, arn in sorted(tables.items()):
        region, named, table = parse_table_arn(arn)
        glue = boto3.client("glue", region_name=region)
        database = named or find_database(glue, table)
        described = glue.get_table(DatabaseName=database, Name=table)["Table"]
        columns = {c["Name"] for c in described.get("StorageDescriptor", {}).get("Columns", [])}
        if not {"time", "metadata"} <= columns:
            schemaless.append(source)
            print(f"lake: {source}: no schema, skipped", file=sys.stderr)
            continue
        athena = boto3.client("athena", region_name=region)
        target = f'"{database}"."{table}"'
        # eventday is the partition, lower-cased by the crawler (SPEC §4.2);
        # filtering on it is what keeps the scan to the days in question.
        found = athena_rows(
            athena,
            f'SELECT metadata.uid, "time" FROM {target} '
            f"WHERE eventday BETWEEN '{day_low}' AND '{day_high}' "
            f'AND "time" BETWEEN {low} AND {high}',
            database,
            workgroup,
            output,
        )
        rows.extend(LakeRow(uid or "", int(t or 0), source) for uid, t in found)
        ((count,),) = athena_rows(
            athena,
            f"SELECT count(*) FROM {target} WHERE eventday = '19700101'",
            database,
            workgroup,
            output,
        )
        undated += int(count or 0)
        print(f"lake: {source}: {len(found)} rows", file=sys.stderr)
    return rows, undated, schemaless


def _event_day(epoch_ms: int) -> str:
    return datetime.fromtimestamp(epoch_ms / 1000, UTC).strftime("%Y%m%d")


# --- the run ----------------------------------------------------------------


def _epoch_ms(bound: str) -> int:
    parsed = datetime.fromisoformat(bound)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp() * 1000)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=Path, required=True, help="the connector's TOML")
    parser.add_argument(
        "--glue-tables",
        type=Path,
        required=True,
        help="JSON from `terraform output -json glue_tables`: source name -> table ARN",
    )
    parser.add_argument("--since", required=True, help="ISO 8601, inclusive")
    parser.add_argument("--until", required=True, help="ISO 8601, exclusive")
    parser.add_argument("--pad-hours", type=float, default=24.0)
    parser.add_argument("--workgroup", default="primary")
    parser.add_argument(
        "--output-location",
        default=None,
        help="s3:// for Athena results, unless the workgroup sets one",
    )
    args = parser.parse_args(argv)

    since_ms, until_ms = _epoch_ms(args.since), _epoch_ms(args.until)
    now = time.time()
    if since_ms >= until_ms:
        print("since must be before until", file=sys.stderr)
        return 2
    if retention_shortfall(args.since, now) > 0:
        print("since is past Okta's 90-day retention; Okta's side would be short", file=sys.stderr)
        return 2
    if until_ms / 1000 > now - SETTLE_HOURS * 3600:
        print(f"until must be at least {SETTLE_HOURS} hours ago (SPEC §2.1)", file=sys.stderr)
        return 2

    tables: dict[str, str] = json.loads(args.glue_tables.read_text())

    okta = asyncio.run(read_okta(args.config, args.since, args.until))
    lake, undated, schemaless = read_lake(
        tables,
        since_ms,
        until_ms,
        timedelta(hours=args.pad_hours),
        args.workgroup,
        args.output_location,
    )
    result = compare(okta, lake, since_ms, until_ms)

    hours = (until_ms - since_ms) / 3_600_000
    print(f"window: {hours:.1f} hours, {len(tables)} source tables")
    print(f"okta:   {result.okta_events} events, {result.okta_unique} unique")
    print(
        f"lake:   {result.lake_rows} rows in the padded window, {undated} undated (epoch partition)"
    )
    for label, uids in (
        ("missing", result.missing),
        ("extra", result.extra),
        ("duplicated", result.duplicated),
        ("cross-class", result.cross_class),
    ):
        line = f"{label + ':':12s}{len(uids)}"
        print(line + (f"  [{fingerprint(uids)}]" if uids else ""))
    print(f"{'blank ids:':12s}{result.blank_uids}")
    if schemaless:
        print(
            f"no schema:  {len(schemaless)} table(s) never received data, skipped: "
            + ", ".join(schemaless)
        )
    if result.okta_events != result.okta_unique:
        print("note: Okta returned some ids more than once; the dedup set exists for that (§5.2)")
    print("CLEAN" if result.clean else "NOT CLEAN")
    return 0 if result.clean else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
