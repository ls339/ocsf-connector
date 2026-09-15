"""Telemetry seam: what this connector says about itself.

docs/SPEC.md §7 lists the signals. Two are named there as rates --
``events_per_second`` and ``error_rate`` -- and are deliberately **not** emitted
as rates. A rate computed in-process is wrong as soon as there is more than one
instance, and wrong again across a restart, because the divisor is whatever
window that process happened to observe. A monotonic counter lets whatever
scrapes it compute the rate over the window the viewer actually asked for. So the
connector counts and the backend divides.

The seam exists so that no module outside this package imports OpenTelemetry, and
so the default is silence: :class:`NullMetrics` satisfies the protocol and does
nothing, which is what every test uses without saying so.

Lag is recorded as a histogram rather than a gauge for the same reason: a p99
ingest lag across a fleet cannot be reconstructed from the last value each
instance happened to hold.
"""

from __future__ import annotations

from typing import Protocol


class Metrics(Protocol):
    """Every signal in SPEC §7, as the connector actually emits it."""

    def count_events(self, events: int, *, stream: str) -> None:
        """Events delivered to the sink. Throughput is this, divided later."""
        ...

    def count_error(self, *, stage: str, stream: str) -> None:
        """One failure, labeled by where it happened.

        ``stage`` is ``source``, ``mapping`` or ``sink`` -- the three are worth
        separating because they fail for unrelated reasons and are fixed by
        different people (§7).
        """
        ...

    def count_unmapped_event_type(self, event_type: str) -> None:
        """A vendor event type the mapping table does not know.

        The source-drift alarm (§3.3). Labeled by type, and counted on every
        occurrence rather than only the first, so a type that starts appearing
        in volume is visible as volume.
        """
        ...

    def count_object_written(self, *, class_uid: int) -> None:
        """One Parquet object landed, labeled by OCSF class.

        Security Lake registers one custom source per class (§4.1), so this is
        per-source health rather than a single number for the sink.
        """
        ...

    def record_ingest_lag(self, seconds: float, *, stream: str) -> None:
        """``now - published`` for the newest event in a page.

        The headline SLI, and the one safe use of ``published``: it says how far
        behind the connector is, never where to resume from (§2.1).
        """
        ...

    def record_commit_lag(self, seconds: float, *, stream: str) -> None:
        """How long the just-committed batch spent un-acked.

        Answers "how much work is at risk of replay right now" (§7), which is
        the operational face of the ack-then-commit rule (§5).
        """
        ...

    def record_rate_limit_remaining(self, remaining: int) -> None:
        """Headroom left in the org's bucket, as Okta last reported it.

        A gauge, not a counter: only the latest value means anything, and the
        quota it is measured against is org-specific (§2.3).
        """
        ...


class NullMetrics:
    """The default: satisfies :class:`Metrics`, says nothing.

    Not a test double -- it is what runs when no telemetry is configured, so the
    connector never requires an observability stack to work.
    """

    def count_events(self, events: int, *, stream: str) -> None:
        return None

    def count_error(self, *, stage: str, stream: str) -> None:
        return None

    def count_unmapped_event_type(self, event_type: str) -> None:
        return None

    def count_object_written(self, *, class_uid: int) -> None:
        return None

    def record_ingest_lag(self, seconds: float, *, stream: str) -> None:
        return None

    def record_commit_lag(self, seconds: float, *, stream: str) -> None:
        return None

    def record_rate_limit_remaining(self, remaining: int) -> None:
        return None
