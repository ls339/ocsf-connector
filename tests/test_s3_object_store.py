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

from collections.abc import Iterator
from typing import Any

import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from ocsf_connector.sinks.objects import ObjectStore
from ocsf_connector.sinks.s3 import RETRY_MODE, S3ObjectStore, s3_client

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
