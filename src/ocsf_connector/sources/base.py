"""Source seam.

A source knows how to authenticate to one vendor API, fetch one page of raw
events, and hand back an opaque cursor for the next page. It knows nothing about
OCSF and nothing about sinks.

The cursor is deliberately opaque: for Okta it is the verbatim ``next`` URL from
the ``Link`` header, which the vendor documents as system-generated and not to be
constructed by clients. Treating it as a string the connector never parses is
what keeps resume correct. See docs/SPEC.md §2.1.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

Cursor = str
"""Opaque resume token. Persisted verbatim; never parsed, never synthesized."""


@dataclass(frozen=True, slots=True)
class Page:
    """One page of raw, un-normalized vendor events."""

    records: list[dict[str, Any]]
    next_cursor: Cursor | None
    """``None`` only in bounded mode, signalling the end of the range.

    In polling mode the vendor always returns a next cursor, even for an empty
    page, so ``records == [] and next_cursor is not None`` means "caught up",
    not "finished".
    """


class Source(Protocol):
    """One vendor API, one log stream."""

    name: str

    async def start_tail(self, since: str) -> Cursor:
        """Open a polling stream and return its first cursor.

        Called only when the state store has no cursor. Once a cursor exists,
        the runner resumes from it and never recomputes a start position from a
        timestamp -- doing so risks skipped or duplicated events.
        """
        ...

    async def start_backfill(self, since: str, until: str) -> Cursor:
        """Open a bounded query over a closed time range."""
        ...

    async def fetch(self, cursor: Cursor) -> Page:
        """Fetch one page. Handles auth renewal, retries, and rate limiting.

        Raises only on non-recoverable failures; 429s and transient 5xx are
        absorbed internally with jittered backoff.
        """
        ...
