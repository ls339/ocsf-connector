"""Tail and backfill: the composition root.

Everything this connector does is assembled here and nowhere else -- which is
why the seams elsewhere take their collaborators as arguments and none of them
reach for a global. docs/SPEC.md §6 describes the two modes; the loop they share
is `runner/loop.py`, and only the opening cursor and the termination condition
differ.

Two obligations land in this file specifically because the runner cannot enforce
them:

**Tail's opening ``since`` comes from configuration.** The runner has no way to
know how ``start`` computed its answer (§5.2), so the rule that it must not be
``now()`` lives here -- satisfied by `config.okta.since` having no default.

**The two modes must not share a stream name.** The state store is keyed by
stream, so a backfill sharing tail's name would overwrite tail's cursor. They
default to different names. The dedup seen-set is deliberately *not* per stream,
which is what keeps the overlap safe where a backfill range meets the tail.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

from ocsf_connector.config import Config, MissingConfig
from ocsf_connector.mapping.okta import OktaOcsfMapper
from ocsf_connector.runner.loop import RunStats, run
from ocsf_connector.sinks.objects import LocalObjectStore
from ocsf_connector.sinks.security_lake import SecurityLakeSink
from ocsf_connector.sources.okta.auth import BearerAuth, DpopAuth, OktaClientCredentials
from ocsf_connector.sources.okta.source import OktaSource
from ocsf_connector.state.sqlite import SqliteStateStore
from ocsf_connector.telemetry.base import Metrics, NullMetrics
from ocsf_connector.telemetry.otel import OtelMetrics

TAIL_STREAM = "okta-tail"
BACKFILL_STREAM = "okta-backfill"


class ColdStartRefused(RuntimeError):
    """Tail has no cursor to resume from and was not told to start fresh.

    The connector cannot tell a genuine first run from a lost one: an empty
    database is what both look like. ``mkdir(parents=True, exist_ok=True)``
    below happily creates a state directory wherever the process was launched,
    and SQLite creates the file on connect, so neither layer can raise. Left to
    itself the runner would call ``start`` and open from ``okta.since``,
    re-ingesting everything since that bound without a word.

    Rather than guess, tail refuses and asks. ``--from-scratch`` is how an
    operator says "yes, there is genuinely nothing to resume". Backfill needs no
    such guard: its bounds are already explicit on the command line.
    """


@dataclass(slots=True)
class Assembled:
    """The parts, wired together and ready to run."""

    source: OktaSource
    mapper: OktaOcsfMapper
    sink: SecurityLakeSink
    store: SqliteStateStore
    metrics: Metrics

    def close(self) -> None:
        self.store.close()


def assemble(config: Config, client: httpx.AsyncClient) -> Assembled:
    """Build the pipeline from configuration.

    Reads the key material once, here, at startup: a file that becomes
    unreadable later cannot then break a connector that is already running.
    """
    metrics: Metrics = OtelMetrics() if config.telemetry.enabled else NullMetrics()

    credentials = OktaClientCredentials(
        org_url=config.okta.org_url,
        client_id=config.okta.client_id,
        private_key=config.okta.private_key_file.read_text(),
        kid=config.okta.kid,
        client=client,
    )
    # The app either requires proof-of-possession or does not; naming a DPoP key
    # is how an operator says which (§2.4). Getting it wrong fails at the first
    # token request with a message naming the other class.
    auth = (
        DpopAuth(credentials, dpop_key=config.okta.dpop_key_file.read_text())
        if config.okta.dpop_key_file is not None
        else BearerAuth(credentials)
    )

    config.state.database.parent.mkdir(parents=True, exist_ok=True)
    store = SqliteStateStore(config.state.database, ttl_seconds=config.state.ttl_hours * 3600)

    # The mapper counts unknown event types; this is the wire that turns that
    # count into the drift alarm (§3.3, §7).
    mapper = OktaOcsfMapper(on_unmapped=metrics.count_unmapped_event_type)

    return Assembled(
        source=OktaSource(
            org_url=config.okta.org_url,
            client=client,
            auth=auth,
            limit=config.okta.limit,
            metrics=metrics,
        ),
        mapper=mapper,
        sink=SecurityLakeSink(
            store=LocalObjectStore(config.sink.directory),
            source_name=config.sink.source_name,
            region=config.sink.region,
            account_id=config.sink.account_id,
            metrics=metrics,
        ),
        store=store,
        metrics=metrics,
    )


async def tail(config: Config, *, from_scratch: bool = False) -> RunStats:
    """Follow the stream forever, sleeping when caught up.

    Never returns on its own: a polling query always carries a next link, so an
    empty page means "caught up", not "finished" (§2.2).

    Raises :class:`MissingConfig` when no opening bound is configured. This is
    the obligation §5.2 places on the mode entry point, and it is checked here
    rather than defaulted anywhere: the connector would rather refuse to start
    than invent a bound whose value changes between restarts.

    Raises :class:`ColdStartRefused` when the stream has no committed cursor and
    ``from_scratch`` was not set -- the same instinct applied to state rather
    than to configuration.
    """
    if config.okta.since is None:
        raise MissingConfig(
            "tail needs okta.since in the configuration: the opening bound must be "
            "the same after a restart, so it cannot be computed at startup (SPEC §5.2)"
        )

    since = config.okta.since
    stream = config.stream or TAIL_STREAM
    async with httpx.AsyncClient() as client:
        parts = assemble(config, client)
        try:
            # Checked after assembling, because assembling is what opens (and
            # creates) the database: asking first would report "no cursor" for a
            # file that does not exist yet, which is a different problem.
            if not from_scratch and await parts.store.get_cursor(stream) is None:
                raise ColdStartRefused(
                    f"no committed cursor for stream {stream!r} in "
                    f"{config.state.database}. Tail resumes from the cursor, and with "
                    "none it would open from okta.since and re-ingest everything since "
                    "that bound. Pass --from-scratch if this is genuinely the first run; "
                    "otherwise the connector is pointed at the wrong state database "
                    "(SPEC §5.2)"
                )
            return await run(
                source=parts.source,
                mapper=parts.mapper,
                sink=parts.sink,
                store=parts.store,
                stream=stream,
                # From configuration, never now(). See §5.2 and this module's
                # docstring -- the runner cannot check this for us.
                start=lambda: parts.source.start_tail(since),
                on_idle=lambda: asyncio.sleep(config.okta.poll_seconds),
                metrics=parts.metrics,
            )
        finally:
            parts.close()


async def backfill(config: Config, *, since: str, until: str) -> RunStats:
    """Walk a closed range and stop when Okta stops offering a next link (§2.2).

    Both bounds are arguments rather than configuration: a backfill is a
    question someone asks once, and its answer should not require editing a file
    that a long-running tail also reads.
    """
    async with httpx.AsyncClient() as client:
        parts = assemble(config, client)
        try:
            return await run(
                source=parts.source,
                mapper=parts.mapper,
                sink=parts.sink,
                store=parts.store,
                stream=config.stream or BACKFILL_STREAM,
                start=lambda: parts.source.start_backfill(since, until),
                metrics=parts.metrics,
            )
        finally:
            parts.close()
