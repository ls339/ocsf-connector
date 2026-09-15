"""OpenTelemetry implementation of the telemetry seam (docs/SPEC.md §7).

The only module in the connector that imports OpenTelemetry. Everything else
depends on :class:`~ocsf_connector.telemetry.base.Metrics`, so swapping the
backend -- or running with none at all -- touches nothing but this file.

Constructing this without an SDK configured is safe: the API hands back proxy
instruments that accept calls and discard them. That matters because the
alternative -- making the connector require a configured exporter to start -- is
how observability ends up switched off in the environments that need it most.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from opentelemetry import metrics

# ``_Gauge`` rather than ``Gauge`` is deliberate, and not a typo to tidy up: the
# synchronous gauge is still provisional in OpenTelemetry 1.44, so the package
# exports it under that name -- it is in ``opentelemetry.metrics.__all__``. The
# unprefixed ``Gauge`` exists only inside ``metrics._internal``, which is a
# private module and a worse thing to depend on.
from opentelemetry.metrics import Counter, Histogram, Meter, _Gauge

INSTRUMENTATION_NAME = "ocsf_connector"


@dataclass(slots=True)
class OtelMetrics:
    """Implements :class:`~ocsf_connector.telemetry.base.Metrics`.

    Instrument names are the ones SPEC §7 lists, with the two rates emitted as
    the counters they are derived from: ``events_total`` rather than
    ``events_per_second``, ``errors_total`` rather than ``error_rate``.
    """

    meter: Meter = field(default_factory=lambda: metrics.get_meter(INSTRUMENTATION_NAME))
    _events: Counter = field(init=False)
    _errors: Counter = field(init=False)
    _unmapped: Counter = field(init=False)
    _objects: Counter = field(init=False)
    _ingest_lag: Histogram = field(init=False)
    _commit_lag: Histogram = field(init=False)
    _rate_limit: _Gauge = field(init=False)

    def __post_init__(self) -> None:
        self._events = self.meter.create_counter(
            "events_total", unit="1", description="OCSF events delivered to the sink"
        )
        self._errors = self.meter.create_counter(
            "errors_total", unit="1", description="Failures, by pipeline stage"
        )
        self._unmapped = self.meter.create_counter(
            "unmapped_event_type_total",
            unit="1",
            description="Vendor event types absent from the mapping table",
        )
        self._objects = self.meter.create_counter(
            "parquet_objects_written",
            unit="1",
            description="Parquet objects landed, by OCSF class",
        )
        self._ingest_lag = self.meter.create_histogram(
            "ingest_lag_seconds", unit="s", description="now - published, per page"
        )
        self._commit_lag = self.meter.create_histogram(
            "cursor_commit_lag_seconds",
            unit="s",
            description="How long a batch spent un-acked before its cursor committed",
        )
        self._rate_limit = self.meter.create_gauge(
            "rate_limit_remaining",
            unit="1",
            description="Requests left in the org's bucket, as Okta last reported",
        )

    def count_events(self, events: int, *, stream: str) -> None:
        self._events.add(events, {"stream": stream})

    def count_error(self, *, stage: str, stream: str) -> None:
        self._errors.add(1, {"stage": stage, "stream": stream})

    def count_unmapped_event_type(self, event_type: str) -> None:
        self._unmapped.add(1, {"event_type": event_type})

    def count_object_written(self, *, class_uid: int) -> None:
        self._objects.add(1, {"class_uid": class_uid})

    def record_ingest_lag(self, seconds: float, *, stream: str) -> None:
        self._ingest_lag.record(seconds, {"stream": stream})

    def record_commit_lag(self, seconds: float, *, stream: str) -> None:
        self._commit_lag.record(seconds, {"stream": stream})

    def record_rate_limit_remaining(self, remaining: int) -> None:
        self._rate_limit.set(remaining)
