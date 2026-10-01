"""The S3 destination.

Tested with ``botocore.stub.Stubber`` rather than a fake AWS, which is a
deliberate choice worth stating. What this store has to get right is which call
it makes, with which parameters, and that a failure reaches the caller instead
of being swallowed -- and Stubber validates parameters against botocore's own
service model, so a misspelled argument fails here rather than being accepted by
a fake that shrugs. The properties it cannot show are S3's own (a PUT is durable
when it returns; the same key twice leaves one object), and asserting those
against a fake asserts the fake. They belong in `scripts/s3_probe.py`, against a
real bucket, as `scripts/live_probe.py` already does for Okta.

That a replayed batch re-derives the same key is not S3's property but ours, and
it is tested where it lives: the sink's digest-of-the-opening-cursor
(tests/test_security_lake_sink.py) and LocalObjectStore (tests/test_object_store.py).

Synthetic throughout: no real bucket, account or region-specific identifier
(CLAUDE.md invariant 5).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from ocsf_connector.sinks.objects import ObjectStore
from ocsf_connector.sinks.s3 import (
    RENEWAL_MARGIN,
    RETRY_MODE,
    ProviderRoles,
    S3ObjectStore,
    UnregisteredSource,
    s3_client,
)

BUCKET = "synthetic-security-data-lake"
REGION = "us-east-1"
SOURCE = "okta_authentication"
PARTITION = "region=us-east-1/accountId=external_synthetic/eventDay=20260905/abc.parquet"
KEY = f"ext/{SOURCE}/{PARTITION}"
BODY = b"parquet-bytes"


@pytest.fixture
def store() -> Iterator[tuple[S3ObjectStore, Stubber]]:
    client: Any = s3_client(
        REGION, aws_access_key_id="synthetic", aws_secret_access_key="synthetic"
    )
    stubber = Stubber(client)
    stubber.activate()
    yield S3ObjectStore(bucket=BUCKET, region=REGION, client=client), stubber
    stubber.deactivate()


async def test_an_object_goes_to_the_sources_own_prefix(
    store: tuple[S3ObjectStore, Stubber],
) -> None:
    """The prefix AWS documents for a custom source, built from the source the
    caller named rather than recovered from the key (§4.2)."""
    s3, stubber = store
    stubber.add_response(
        "put_object",
        {},
        {"Bucket": BUCKET, "Key": KEY, "Body": BODY},
    )

    await s3.put(SOURCE, PARTITION, BODY)

    stubber.assert_no_pending_responses()
    assert s3.written == [KEY]


async def test_two_sources_go_to_two_prefixes(store: tuple[S3ObjectStore, Stubber]) -> None:
    """Two classes flushed from one batch derive the same key, so the source is
    the only thing keeping them apart (§4.2). Here that is two Keys, not one."""
    s3, stubber = store
    for source in ("okta_authentication", "okta_account_change"):
        stubber.add_response(
            "put_object",
            {},
            {"Bucket": BUCKET, "Key": f"ext/{source}/{PARTITION}", "Body": BODY},
        )

    await s3.put("okta_authentication", PARTITION, BODY)
    await s3.put("okta_account_change", PARTITION, BODY)

    stubber.assert_no_pending_responses()
    assert s3.written == [
        f"ext/okta_authentication/{PARTITION}",
        f"ext/okta_account_change/{PARTITION}",
    ]


async def test_a_failed_put_reaches_the_caller(store: tuple[S3ObjectStore, Stubber]) -> None:
    """The whole delivery guarantee rests on this. A swallowed error means the
    flush returns cleanly, the runner commits a cursor past events that were
    never written, and the events are gone with nothing raised (§5)."""
    s3, stubber = store
    stubber.add_client_error("put_object", service_error_code="AccessDenied", http_status_code=403)

    with pytest.raises(ClientError):
        await s3.put(SOURCE, PARTITION, BODY)

    assert s3.written == [], "and a write that failed is not recorded as one"


async def test_nothing_is_recorded_before_s3_has_it(
    store: tuple[S3ObjectStore, Stubber],
) -> None:
    """``put`` returning is what licenses a cursor commit (§5), so the order
    matters: the acknowledgement comes first and the bookkeeping second."""
    s3, stubber = store
    seen: list[list[str]] = []
    original = s3.client.put_object

    def watching(**kwargs: Any) -> Any:
        seen.append(list(s3.written))
        return original(**kwargs)

    s3.client.put_object = watching
    stubber.add_response("put_object", {}, {"Bucket": BUCKET, "Key": KEY, "Body": BODY})

    await s3.put(SOURCE, PARTITION, BODY)

    assert seen == [[]], "written was still empty while the PUT was in flight"
    assert s3.written == [KEY]


def test_the_retry_mode_is_chosen_not_inherited() -> None:
    """botocore defaults to ``legacy``. A delivery path should not inherit a
    retry set nobody picked, so ``standard`` is asked for explicitly."""
    client = s3_client(REGION, aws_access_key_id="synthetic", aws_secret_access_key="synthetic")

    assert RETRY_MODE == "standard"
    assert client.meta.config.retries["mode"] == "standard"


def test_the_store_satisfies_the_object_store_protocol() -> None:
    """Structural, so nothing declares it. This is the assertion that the seam
    and its S3 implementation have not drifted apart."""

    def takes_store(store: ObjectStore) -> ObjectStore:
        return store

    assert takes_store(S3ObjectStore(bucket=BUCKET, region=REGION, client=object())) is not None


# --- provider roles ----------------------------------------------------------
#
# Security Lake does not let a provider write the lake bucket directly: it
# creates a role per custom source, scoped to that source's prefix, trusted to
# the principal and external id given at registration (§4.2). These assert what
# the connector does with that, including the renewal -- which is invisible from
# outside, since a renewed client writes exactly like a fresh one.


class FakeSts:
    """Hands out credentials that expire when the test says they do."""

    def __init__(self, lifetime: float = 3600.0, now: float = 1_000_000.0) -> None:
        self.lifetime = lifetime
        self.now = now
        self.calls: list[dict[str, Any]] = []

    def assume_role(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        issued = len(self.calls)
        return {
            "Credentials": {
                "AccessKeyId": f"ASIASYNTHETIC{issued}",
                "SecretAccessKey": f"secret-{issued}",
                "SessionToken": f"token-{issued}",
                "Expiration": datetime.fromtimestamp(self.now + self.lifetime, tz=UTC),
            }
        }


def roles_for(
    sts: FakeSts, clock: Callable[[], float], built: list[dict[str, Any]] | None = None
) -> ProviderRoles:
    def factory(region: str, **credentials: Any) -> Any:
        if built is not None:
            built.append({"region": region, **credentials})
        return object()

    # Shaped like a real one, with a synthetic account. The path is the part this
    # connector does not guess -- these come from terraform output (§4.2).
    def role(source: str) -> str:
        return f"arn:aws:iam::000000000000:role/AmazonSecurityLake-Provider-{source}-{REGION}"

    return ProviderRoles(
        roles={
            "okta_authentication": role("okta_authentication"),
            "okta_account_change": role("okta_account_change"),
        },
        external_id="synthetic-external-id",
        region=REGION,
        sts=sts,
        client_factory=factory,
        clock=clock,
    )


def test_a_source_is_written_by_the_role_registered_for_it() -> None:
    """One role per source, assumed with the external id those roles trust."""
    sts = FakeSts()
    roles = roles_for(sts, lambda: 1_000_000.0)

    roles.client_for("okta_authentication")

    (call,) = sts.calls
    assert call["RoleArn"].endswith("AmazonSecurityLake-Provider-okta_authentication-us-east-1")
    assert call["ExternalId"] == "synthetic-external-id", "without it every assume-role is refused"
    assert call["RoleSessionName"], "CloudTrail shows this on every write the role makes"


def test_credentials_are_reused_until_the_renewal_margin() -> None:
    """A tail flushes every five minutes for weeks. Assuming a role per PUT would
    be an STS call per object for no benefit, and STS is rate limited."""
    sts = FakeSts(lifetime=3600.0, now=1_000_000.0)
    now = 1_000_000.0
    roles = roles_for(sts, lambda: now)

    first = roles.client_for("okta_authentication")
    # 2879, not 3600 * RENEWAL_MARGIN - 1. A threshold computed from the constant
    # under test moves with it, so a margin of 1.0 would satisfy every one of
    # these tests while renewing at the moment of expiry.
    now = 1_000_000.0 + 2879.0
    again = roles.client_for("okta_authentication")

    assert again is first
    assert roles.assumed == 1, "one assume-role, two writes"


def test_credentials_are_renewed_once_the_margin_passes() -> None:
    """Margin-based, not failure-driven: a 403 for expired credentials is already
    a failed flush, and the same instinct as the Okta token's renewal (§2.4)."""
    sts = FakeSts(lifetime=3600.0, now=1_000_000.0)
    now = 1_000_000.0
    roles = roles_for(sts, lambda: now)

    first = roles.client_for("okta_authentication")
    now = 1_000_000.0 + 2881.0  # literal: see the note on reuse above
    renewed = roles.client_for("okta_authentication")

    assert renewed is not first
    assert roles.assumed == 2
    assert len(sts.calls) == 2


def test_the_renewal_margin_pays_for_the_round_trip() -> None:
    """Measured from before the call, not after. A slow STS response would
    otherwise extend the window in which credentials are trusted past what they
    are actually good for."""
    sts = FakeSts(lifetime=1000.0, now=1_000_000.0)
    readings = iter([1_000_000.0, 1_000_000.0 + 800.0 - 1])
    roles = roles_for(sts, lambda: next(readings))

    roles.client_for("okta_authentication")

    cached = roles._cached["okta_authentication"]
    assert cached.renew_at == pytest.approx(1_000_000.0 + 800.0), (
        "800, not 1000 * RENEWAL_MARGIN -- an expectation read from the constant "
        "cannot fail when the constant is wrong"
    )


def test_the_margin_leaves_room_rather_than_renewing_at_expiry() -> None:
    """Pinned literally, because every timing above is a literal for this reason.

    A margin of 1.0 means asking for new credentials at the instant the old ones
    die, which in practice means a PUT presenting credentials that expired while
    it was in flight. The value is the one verified live for the Okta token
    renewing at 80.0% of a 3600-second lifetime (§2.4).
    """
    assert RENEWAL_MARGIN == 0.8


def test_each_source_gets_its_own_credentials() -> None:
    """The point of the whole arrangement: a role that may write one prefix. One
    client shared across sources would mean one role writing all of them, which
    is the broad access this design exists to avoid."""
    sts = FakeSts()
    built: list[dict[str, Any]] = []
    roles = roles_for(sts, lambda: 1_000_000.0, built)

    one = roles.client_for("okta_authentication")
    two = roles.client_for("okta_account_change")

    assert one is not two
    assert roles.assumed == 2
    assert [credentials["aws_session_token"] for credentials in built] == ["token-1", "token-2"]
    assert {call["RoleArn"] for call in sts.calls} == set(roles.roles.values())


async def test_a_source_with_no_role_raises_rather_than_guessing() -> None:
    """A class whose custom source was never registered. Raising leaves the
    cursor where it is, so the batch replays once the source exists; writing it
    somewhere plausible would leave objects no table points at (§4.2)."""
    store = S3ObjectStore(
        bucket=BUCKET, region=REGION, roles=roles_for(FakeSts(), lambda: 1_000_000.0)
    )

    with pytest.raises(UnregisteredSource, match="okta_group"):
        await store.put("okta_group", PARTITION, BODY)

    assert store.written == []


async def test_without_roles_the_callers_own_credentials_are_used(
    store: tuple[S3ObjectStore, Stubber],
) -> None:
    """The plain-bucket case stays exactly as it was: no STS, no roles, one
    client. It is how the write path is verified without a Security Lake."""
    s3, stubber = store
    stubber.add_response("put_object", {}, {"Bucket": BUCKET, "Key": KEY, "Body": BODY})

    await s3.put(SOURCE, PARTITION, BODY)

    assert s3.roles is None
    stubber.assert_no_pending_responses()
