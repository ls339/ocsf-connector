"""The destination that actually delivers.

Implements :class:`~ocsf_connector.sinks.objects.ObjectStore` against S3. Every
correctness-relevant decision here is about one sentence in the seam: ``put``
returns only once the object is durable, because that return is what licenses the
runner to commit its cursor (docs/SPEC.md §5).

**One PUT per object, and no multipart.** A PUT is durable when it returns, and
the sink's buffer ceiling is 256 MB (§4) -- comfortably inside what a single PUT
accepts. Multipart would add an upload that can be half-finished, which is a
second kind of partial state for the commit order to reason about, in exchange
for a size this connector does not produce.

**Retries are botocore's, and configured rather than inherited.** botocore's
default mode is ``legacy``; ``standard`` is the documented modern set and is
asked for explicitly here. Beyond it there is no retry loop, deliberately: a
failed flush leaves the cursor where it was, so the batch replays on the next
run and overwrites its own object (§5.2). That is the same recovery a crash
gets, already tested, and it needs no code. Whether a tighter in-sink retry is
worth having is an open question in SPEC §4.2 that wants real failures, not a
guess.

**Blocking calls run in a thread.** boto3 is synchronous and its clients are
safe to call from several threads; ``asyncio.to_thread`` keeps the event loop
free without a second AWS library whose botocore pin would have to agree with
this one's.

**Whose credentials.** Today, the caller's own -- boto3's default chain -- which
is all a plain bucket needs and is how this store is verified before any
Security Lake exists. A registered custom source is instead written by a role
Security Lake creates per source (§4.2), so the client a PUT uses depends on the
source; ``_client_for`` is the one place that has to change, and nothing above it
does.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.config import Config as BotoConfig

RETRY_MODE = "standard"
"""Asked for explicitly: botocore defaults to ``legacy`` (verified against
botocore 1.43), and a delivery path should not inherit a retry set nobody chose.
"""


def s3_client(region: str, **overrides: Any) -> Any:
    """A client configured the way this connector wants one.

    Separate from the store so a test can hand in a client to stub, and so the
    configuration below is stated once rather than per call site.
    """
    return boto3.client(
        "s3",
        region_name=region,
        config=BotoConfig(retries={"mode": RETRY_MODE}),
        **overrides,
    )


@dataclass(slots=True)
class S3ObjectStore:
    """Implements :class:`~ocsf_connector.sinks.objects.ObjectStore` over S3.

    ``bucket`` is where objects land. ``prefix_for`` derives the prefix a custom
    source owns, which AWS documents as ``ext/{source}/`` (§4) -- derived rather
    than configured, because one bucket name is the whole configuration in the
    common case. When registration reports a location that disagrees, that is a
    startup check with something to compare against, and it belongs with the
    per-source roles it arrives alongside (§4.2).
    """

    bucket: str
    region: str
    client: Any = None
    written: list[str] = field(default_factory=list)
    """Keys in the order they were PUT. A replayed write appears twice here while
    leaving one object, which is what makes idempotency observable -- the same
    affordance the local store offers, for the same reason."""

    def __post_init__(self) -> None:
        if self.client is None:
            self.client = s3_client(self.region)

    async def put(self, source: str, key: str, data: bytes) -> None:
        """PUT ``data`` for ``source``. Returns only once S3 has it (§5).

        Errors are not caught. A raise here fails the flush, the runner does not
        commit, and the batch replays into the same key -- so the failure mode is
        a repeated write rather than a lost one.
        """
        full_key = self.key_for(source, key)
        await asyncio.to_thread(
            self._client_for(source).put_object,
            Bucket=self.bucket,
            Key=full_key,
            Body=data,
        )
        self.written.append(full_key)

    @staticmethod
    def prefix_for(source: str) -> str:
        """The prefix Security Lake assigns a custom source (§4)."""
        return f"ext/{source}"

    def key_for(self, source: str, key: str) -> str:
        """Where an object lands in the bucket."""
        return f"{self.prefix_for(source)}/{key}"

    def _client_for(self, source: str) -> Any:
        """The client that may write ``source``.

        One client for every source today, because the caller's own credentials
        are what a plain bucket accepts. A registered source is written by
        ``AmazonSecurityLake-Provider-{source}-{region}``, assumed with an
        external id (§4.2), so this becomes a per-source lookup with its own
        session cache. Keeping the indirection to one method is the whole point:
        no caller has to learn that the answer became source-dependent.
        """
        return self.client
