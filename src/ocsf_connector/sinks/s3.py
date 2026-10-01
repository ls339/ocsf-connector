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

**Whose credentials.** Either the caller's own -- boto3's default chain, which is
all a plain bucket needs -- or, for a registered custom source, the role Security
Lake created for that source. See :class:`ProviderRoles`. Which one is in use is
decided by configuration and resolved in ``_client_for``; nothing above that
method knows the difference.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.config import Config as BotoConfig

RENEWAL_MARGIN = 0.8
"""Re-assume a provider role once this much of its credentials' lifetime has
elapsed.

The same margin, for the same reason, as the Okta token in
`sources/okta/auth.py` -- where it was verified live renewing at 80.0% of a
3600-second lifetime. Not imported from there: a sink must not depend on a
source, which is the layering the `ocsf/` package exists to protect. Two
declarations of one number is the cheaper mistake.
"""

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


class UnregisteredSource(LookupError):
    """No provider role for a source the sink tried to write.

    A wiring mistake rather than a runtime failure: an OCSF class acquired a
    source name and nobody registered a custom source for it. Raised rather than
    written somewhere plausible, because the cursor then stays where it is and
    the batch replays once the source exists -- where guessing a destination
    would leave objects nothing points at (§4.2).
    """


@dataclass(slots=True)
class _Assumed:
    """One role's credentials, and when to stop trusting them."""

    client: Any
    renew_at: float


@dataclass(slots=True)
class ProviderRoles:
    """Write credentials for registered custom sources, assumed and renewed.

    Security Lake does not let a provider write the lake bucket directly. For each
    custom source it creates ``AmazonSecurityLake-Provider-{source}-{region}``,
    scoped to that source's prefix alone, and trusts the principal and external id
    given at registration (§4.2). So the connector assumes one role per source,
    and a compromised connector can write one prefix rather than a bucket.

    ``roles`` comes from registration -- `terraform output provider_roles` -- and
    is not derived. AWS documents the role *name*, which the terraform follows,
    but a role's ARN may carry a path, and a guessed path fails at the first PUT
    rather than at startup.

    Credentials are cached per source and re-assumed at
    :data:`RENEWAL_MARGIN` of their lifetime, read from the response rather than
    assumed to be an hour: a role's maximum session duration is the role's
    business. If they expire anyway -- a clock far enough out of step -- the PUT
    raises, the flush fails, the cursor does not move, and the replay mints fresh
    ones. That is the recovery every other failure here gets, which is why there
    is no retry.

    Single-writer by construction: the runner flushes one batch at a time and the
    sink writes its objects in sequence, so the cache is never entered
    concurrently. A sink that ever writes objects in parallel needs a lock here,
    and this sentence is the warning.
    """

    roles: Mapping[str, str]
    external_id: str
    region: str
    sts: Any = None
    client_factory: Callable[..., Any] = s3_client
    clock: Callable[[], float] = time.time
    session_name: str = "ocsf-connector"
    assumed: int = field(default=0, init=False)
    """How many times a role has been assumed. The renewal is invisible from
    outside -- a renewed client writes exactly like a fresh one -- so this is what
    makes "it reused the credentials" testable at all."""
    _cached: dict[str, _Assumed] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        if self.sts is None:
            self.sts = boto3.client(
                "sts",
                region_name=self.region,
                config=BotoConfig(retries={"mode": RETRY_MODE}),
            )

    def client_for(self, source: str) -> Any:
        cached = self._cached.get(source)
        if cached is not None and self.clock() < cached.renew_at:
            return cached.client
        return self._assume(source).client

    def _assume(self, source: str) -> _Assumed:
        role_arn = self.roles.get(source)
        if role_arn is None:
            raise UnregisteredSource(
                f"no provider role for custom source {source!r}. Security Lake creates "
                "one per source at registration; until it exists there is nowhere this "
                "class's objects may be written (SPEC §4.2)"
            )

        requested_at = self.clock()
        response = self.sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=self.session_name,
            ExternalId=self.external_id,
        )
        credentials = response["Credentials"]
        # Measured from the clock reading taken *before* the call, so the margin
        # pays for the round trip rather than assuming it was free.
        lifetime = credentials["Expiration"].timestamp() - requested_at
        assumed = _Assumed(
            client=self.client_factory(
                self.region,
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
            ),
            renew_at=requested_at + lifetime * RENEWAL_MARGIN,
        )
        self._cached[source] = assumed
        self.assumed += 1
        return assumed


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
    roles: ProviderRoles | None = None
    """Set when writing registered custom sources. Left unset, every write uses
    the caller's own credentials, which is what a plain bucket accepts."""
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
        # Resolving the client can itself call AWS -- assuming a role, or renewing
        # one -- so it happens inside the worker thread with the PUT rather than
        # on the event loop.
        await asyncio.to_thread(self._put, source, full_key, data)
        self.written.append(full_key)

    def _put(self, source: str, full_key: str, data: bytes) -> None:
        self._client_for(source).put_object(Bucket=self.bucket, Key=full_key, Body=data)

    @staticmethod
    def prefix_for(source: str) -> str:
        """The prefix Security Lake assigns a custom source (§4)."""
        return f"ext/{source}"

    def key_for(self, source: str, key: str) -> str:
        """Where an object lands in the bucket."""
        return f"{self.prefix_for(source)}/{key}"

    def _client_for(self, source: str) -> Any:
        """The client that may write ``source``.

        With provider roles configured, one client per source, assumed and
        renewed by :class:`ProviderRoles`. Without them, the caller's own
        credentials, which is what a plain bucket accepts. Keeping the choice in
        one method is the point: no caller has to learn that the answer became
        source-dependent.
        """
        if self.roles is None:
            return self.client
        return self.roles.client_for(source)
