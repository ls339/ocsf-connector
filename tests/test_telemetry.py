"""Telemetry: the seam, the OpenTelemetry implementation, and the wiring.

Three things worth testing separately, because they fail for different reasons:
the instruments carry the names and labels SPEC §7 specifies; the modules that
hold the signals actually emit them; and the default is silence, so nothing here
is required for the connector to run.

Synthetic throughout (CLAUDE.md invariant 5).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader

from ocsf_connector.mapping.okta import OktaOcsfMapper
from ocsf_connector.runner.loop import run
from ocsf_connector.sinks.objects import LocalObjectStore
from ocsf_connector.sinks.security_lake import SecurityLakeSink
from ocsf_connector.sources.okta.source import OktaSource
from ocsf_connector.state.memory import InMemoryStateStore
from ocsf_connector.telemetry.base import Metrics, NullMetrics
from ocsf_connector.telemetry.otel import OtelMetrics
from tests.doubles import (
    BASE_TIME_MS,
    CountingMapper,
    FailingSink,
    RecordingSink,
    ScriptedSource,
    chain,
)

STREAM = "okta-system-log"
ORG = "https://synthetic.okta.example"
LOGS = f"{ORG}/api/v1/logs"


class RecordingMetrics:
    """Implements :class:`Metrics` by remembering the calls, so a wiring test can
    assert what a module emitted without standing up an SDK."""

    def __init__(self) -> None:
        self.events: list[tuple[int, str]] = []
        self.errors: list[tuple[str, str]] = []
        self.unmapped: list[str] = []
        self.objects: list[int] = []
        self.ingest_lag: list[float] = []
        self.commit_lag: list[float] = []
        self.rate_limit: list[int] = []

    def count_events(self, events: int, *, stream: str) -> None:
        self.events.append((events, stream))

    def count_error(self, *, stage: str, stream: str) -> None:
        self.errors.append((stage, stream))

    def count_unmapped_event_type(self, event_type: str) -> None:
        self.unmapped.append(event_type)

    def count_object_written(self, *, class_uid: int) -> None:
        self.objects.append(class_uid)

    def record_ingest_lag(self, seconds: float, *, stream: str) -> None:
        self.ingest_lag.append(seconds)

    def record_commit_lag(self, seconds: float, *, stream: str) -> None:
        self.commit_lag.append(seconds)

    def record_rate_limit_remaining(self, remaining: int) -> None:
        self.rate_limit.append(remaining)


class StaticAuth:
    async def headers(self, method: str, url: str) -> dict[str, str]:
        return {"Authorization": "Bearer synthetic"}


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as http:
        yield http


def collected(reader: InMemoryMetricReader) -> dict[str, list[dict[str, Any]]]:
    """Every emitted metric, as {name: [{value, attributes}, ...]}."""
    data = reader.get_metrics_data()
    out: dict[str, list[dict[str, Any]]] = {}
    for resource in data.resource_metrics:
        for scope in resource.scope_metrics:
            for metric in scope.metrics:
                points = []
                for point in metric.data.data_points:
                    value = getattr(point, "value", None)
                    if value is None:
                        value = getattr(point, "sum", None)
                    points.append({"value": value, "attributes": dict(point.attributes)})
                out.setdefault(metric.name, []).extend(points)
    return out


# --- the instruments --------------------------------------------------------


def test_the_instruments_carry_the_names_and_labels_spec_7_asks_for() -> None:
    """Names are an interface: dashboards and alerts bind to them."""
    reader = InMemoryMetricReader()
    metrics = OtelMetrics(meter=MeterProvider(metric_readers=[reader]).get_meter("test"))

    metrics.count_events(3, stream=STREAM)
    metrics.count_error(stage="sink", stream=STREAM)
    metrics.count_unmapped_event_type("user.mysterious.thing")
    metrics.count_object_written(class_uid=3002)
    metrics.record_ingest_lag(1.5, stream=STREAM)
    metrics.record_commit_lag(0.25, stream=STREAM)
    metrics.record_rate_limit_remaining(42)

    emitted = collected(reader)
    assert emitted["events_total"][0] == {"value": 3, "attributes": {"stream": STREAM}}
    assert emitted["errors_total"][0]["attributes"] == {"stage": "sink", "stream": STREAM}
    assert emitted["unmapped_event_type_total"][0]["attributes"] == {
        "event_type": "user.mysterious.thing"
    }
    assert emitted["parquet_objects_written"][0]["attributes"] == {"class_uid": 3002}
    assert emitted["ingest_lag_seconds"][0]["value"] == 1.5
    assert emitted["cursor_commit_lag_seconds"][0]["value"] == 0.25
    assert emitted["rate_limit_remaining"][0]["value"] == 42


def test_throughput_and_errors_are_counters_not_rates() -> None:
    """SPEC §7 names events_per_second and error_rate; both are emitted as the
    monotonic counters they derive from. A rate computed in-process is wrong
    across instances and wrong again across a restart."""
    reader = InMemoryMetricReader()
    metrics = OtelMetrics(meter=MeterProvider(metric_readers=[reader]).get_meter("test"))

    metrics.count_events(2, stream=STREAM)
    metrics.count_events(3, stream=STREAM)

    emitted = collected(reader)
    assert emitted["events_total"][0]["value"] == 5, "it accumulates"
    assert "events_per_second" not in emitted
    assert "error_rate" not in emitted


def test_metrics_work_with_no_sdk_configured() -> None:
    """The API hands back proxy instruments when nothing is wired up. Requiring
    an exporter to start is how telemetry ends up off where it matters most."""
    metrics = OtelMetrics()

    metrics.count_events(1, stream=STREAM)
    metrics.record_rate_limit_remaining(7)


def test_null_metrics_satisfies_the_protocol() -> None:
    def takes_metrics(metrics: Metrics) -> Metrics:
        return metrics

    assert takes_metrics(NullMetrics()) is not None


# --- the wiring -------------------------------------------------------------


async def test_the_runner_reports_throughput_and_commit_lag() -> None:
    """Throughput counts what reached the sink, not what arrived: a duplicate
    the source re-delivered is not throughput (§2.1). The clock is a fixed tick
    sequence so both lags have exact expected values -- "greater than zero"
    would pass just as happily with the units or the origin wrong."""
    metrics = RecordingMetrics()
    source = ScriptedSource(chain([["a1", "a2"], ["a2", "b1"]]))
    ticks = iter([100.0, 100.5, 101.0, 101.5, 102.0, 102.5, 103.0, 103.5])

    stats = await run(
        source=source,
        mapper=CountingMapper(),
        sink=RecordingSink(),
        store=InMemoryStateStore(),
        stream=STREAM,
        start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
        metrics=metrics,
        clock=lambda: next(ticks),
    )

    assert stats.mapped == 4 and stats.duplicates_skipped == 1
    assert metrics.events == [(2, STREAM), (1, STREAM)], "delivered, not arrived"
    assert metrics.commit_lag == [pytest.approx(1.0), pytest.approx(1.0)], "one per commit"
    # published is epoch milliseconds; lag is seconds.
    assert metrics.ingest_lag[0] == pytest.approx(100.5 - BASE_TIME_MS / 1000)
    assert metrics.ingest_lag[1] == pytest.approx(102.0 - (BASE_TIME_MS + 1000) / 1000)
    assert metrics.errors == []


async def test_a_sink_failure_is_counted_against_the_sink() -> None:
    """Stages are separated because they fail for unrelated reasons (§7)."""
    metrics = RecordingMetrics()
    source = ScriptedSource(chain([["a1"]]))

    with pytest.raises(OSError):
        await run(
            source=source,
            mapper=CountingMapper(),
            sink=FailingSink(),
            store=InMemoryStateStore(),
            stream=STREAM,
            start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
            metrics=metrics,
        )

    assert metrics.errors == [("sink", STREAM)]
    assert metrics.commit_lag == [], "nothing committed, so nothing to report"


async def test_a_source_failure_is_counted_against_the_source() -> None:
    """The other side of the stage label: same runner, different blame."""
    metrics = RecordingMetrics()
    source = ScriptedSource(chain([["a1"]]))
    store = InMemoryStateStore()
    await store.commit(STREAM, "a-cursor-the-vendor-never-issued", [], "okta-2026.09.01")

    async def must_not_be_called() -> str:
        raise AssertionError("a stored cursor must not be recomputed")

    with pytest.raises(KeyError):
        await run(
            source=source,
            mapper=CountingMapper(),
            sink=RecordingSink(),
            store=store,
            stream=STREAM,
            start=must_not_be_called,
            metrics=metrics,
        )

    assert metrics.errors == [("source", STREAM)]


async def test_telemetry_never_sits_between_the_ack_and_the_commit() -> None:
    """docs/SPEC.md §5: nothing belongs in that gap, telemetry included.

    If the lag were recorded between the flush and the commit, a telemetry
    backend having a bad day would strand an acknowledged batch behind an
    uncommitted cursor -- replaying work the sink already took. So: make the
    metrics call explode, and assert the commit happened anyway.
    """

    class ExplodingMetrics(RecordingMetrics):
        def record_commit_lag(self, seconds: float, *, stream: str) -> None:
            raise RuntimeError("telemetry backend down")

    source = ScriptedSource(chain([["a1"]]))
    sink = RecordingSink()
    store = InMemoryStateStore()

    with pytest.raises(RuntimeError):
        await run(
            source=source,
            mapper=CountingMapper(),
            sink=sink,
            store=store,
            stream=STREAM,
            start=lambda: source.start_tail("2026-09-05T00:00:00Z"),
            metrics=ExplodingMetrics(),
        )

    assert sink.flushes == ["c0"], "the sink acknowledged"
    assert store.has_committed(STREAM), "and the cursor committed before telemetry ran"


async def test_the_source_reports_rate_limit_headroom(
    client: httpx.AsyncClient, respx_mock: respx.MockRouter
) -> None:
    """§2.3: the source is the only place that sees these headers."""
    metrics = RecordingMetrics()
    respx_mock.get(url__startswith=LOGS).mock(
        return_value=httpx.Response(
            200,
            json=[],
            headers={
                "Link": f'<{LOGS}?after=p2>; rel="next"',
                "X-Rate-Limit-Remaining": "37",
                "X-Rate-Limit-Reset": "1788566460",
            },
        )
    )
    source = OktaSource(org_url=ORG, client=client, auth=StaticAuth(), metrics=metrics)

    await source.fetch(await source.start_tail("2026-09-05T00:00:00Z"))

    assert metrics.rate_limit == [37]


async def test_the_sink_reports_objects_by_class(tmp_path: Path) -> None:
    metrics = RecordingMetrics()
    sink = SecurityLakeSink(
        store=LocalObjectStore(tmp_path),
        source_name="okta",
        region="us-east-1",
        account_id="external_synthetic",
        metrics=metrics,
    )
    mapper = OktaOcsfMapper()
    session_start = {
        "uuid": "a1",
        "published": "2026-09-05T00:00:01Z",
        "eventType": "user.session.start",
    }
    user_created = {
        "uuid": "b1",
        "published": "2026-09-05T00:00:02Z",
        "eventType": "user.lifecycle.create",
    }
    await sink.write([mapper.map(session_start), mapper.map(user_created)])

    await sink.flush("https://synthetic.okta.example/api/v1/logs?after=x")

    assert sorted(metrics.objects) == [3001, 3002], "one per class, not one per flush"


async def test_the_mappers_drift_hook_feeds_the_counter() -> None:
    """The mapper already counts unknown event types; telemetry is the
    composition root wiring that hook to the counter (§3.3)."""
    metrics = RecordingMetrics()
    mapper = OktaOcsfMapper(on_unmapped=metrics.count_unmapped_event_type)

    mapper.map({"uuid": "a1", "eventType": "user.mysterious.thing"})
    mapper.map({"uuid": "a2", "eventType": "user.mysterious.thing"})

    assert metrics.unmapped == ["user.mysterious.thing"] * 2, "every occurrence, not the first"
