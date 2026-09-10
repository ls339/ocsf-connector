"""Source seam.

A source knows how to authenticate to one vendor API, fetch one page of raw
events, and hand back the cursor for the next page. It knows nothing about OCSF
and nothing about sinks.

A cursor is *the URL to GET next*. The source builds the **opening** one from a
time range, because a stream has to be opened somehow; every cursor after that is
the ``next`` URL lifted verbatim from the ``Link`` header. What the connector
must never do is construct or read the ``after`` value inside that URL -- the
vendor documents it as system-generated and not to be crafted by clients -- or
derive a resume position from a timestamp. See docs/SPEC.md §2.1 and §2.2.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

Cursor = str
"""The URL to GET next.

Persisted verbatim and never parsed. Only the *opening* cursor is built here, and
only from configured query parameters; every later one comes from the vendor's
``Link`` header. The ``after`` value inside is never constructed or read.
"""


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

        ``since`` MUST come from configuration or a persisted stream origin,
        never from ``now()``. The opening cursor is the first batch's
        ``batch_key``, and a crash before the first commit calls this again: a
        value that moved between the two calls addresses the replayed batch to a
        second object instead of overwriting the first. See docs/SPEC.md §5.2.
        """
        ...

    async def start_backfill(self, since: str, until: str) -> Cursor:
        """Open a bounded query over a closed time range.

        Both bounds are explicit configuration, so the opening cursor is stable
        across restarts by construction -- the constraint ``start_tail`` has to
        state is satisfied here for free.
        """
        ...

    async def fetch(self, cursor: Cursor) -> Page:
        """Fetch one page. Handles auth renewal, retries, and rate limiting.

        Raises only on non-recoverable failures; 429s and transient 5xx are
        absorbed internally with jittered backoff.
        """
        ...
