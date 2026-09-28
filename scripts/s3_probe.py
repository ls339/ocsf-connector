"""One-shot probe of the S3 destination against a real bucket (docs/SPEC.md §5).

CI never runs this: CI has no credentials and makes no live calls. It exists to
answer the questions no fixture can settle, because they are properties of S3
rather than of this code, and asserting them against a fake asserts the fake:

1. **Is a PUT durable when it returns?** ``Sink.flush`` returning is what
   licenses the runner to commit its cursor (§5). If an object is not really
   there once ``put`` has returned, the whole delivery guarantee is a story.
2. **Does writing the same place twice leave one object?** Exactly-once at the
   sink rests on the replayed batch overwriting rather than adding (§5.2). Here
   that is one key holding the second body.
3. **Do these credentials actually permit the write?** The reply to a PUT the
   caller may not make is an error, not a silence, and it should reach the
   caller (§5).

It needs no Security Lake. Any bucket you own is enough, which is the point --
the write path can be proven before a delegated administrator exists or a custom
source is registered (§4.2). What this does *not* cover is what registration
adds: whether the prefix matches the location Security Lake reports, and whether
the per-source provider role permits the PUT.

It writes through `S3ObjectStore` rather than calling boto3 itself, so a pass is
evidence about the connector and not about the probe.

Nothing is created and nothing pre-existing is touched: the bucket must already
exist, every key is written under a probe prefix, and the two objects it wrote
are deleted before it exits (pass ``--keep`` to leave them). Output carries the
bucket name you supplied, the keys under that prefix, and nothing else -- no
event data, no credentials, no account id.

Usage::

    export OCSF_PROBE_BUCKET=a-bucket-you-own
    export AWS_PROFILE=...            # or any credentials boto3 can find
    export AWS_REGION=us-east-1       # must be the bucket's region
    uv run python scripts/s3_probe.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from typing import Any

from ocsf_connector.sinks.s3 import S3ObjectStore

SOURCE = "ocsf_probe"
"""Not one of the connector's real custom source names, so a probe run cannot be
mistaken for delivered data if anything is left behind."""


async def main() -> int:
    bucket = os.environ.get("OCSF_PROBE_BUCKET")
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if not bucket or not region:
        print("set OCSF_PROBE_BUCKET and AWS_REGION", file=sys.stderr)
        return 2

    run = uuid.uuid4().hex[:12]
    partition = f"region={region}/accountId=external_probe/eventDay=19700101/{run}.parquet"
    store = S3ObjectStore(bucket=bucket, region=region)
    client: Any = store.client
    key = store.key_for(SOURCE, partition)
    print(f"bucket: {bucket}  region: {region}")
    print(f"key:    {key}")

    try:
        await store.put(SOURCE, partition, b"first-write")

        # 1. Durable when put returned, not eventually.
        head = client.head_object(Bucket=bucket, Key=key)
        print(f"durable on return: yes ({head['ContentLength']} bytes)")

        # 2. The same place twice.
        await store.put(SOURCE, partition, b"second-write")
        listed = client.list_objects_v2(Bucket=bucket, Prefix=key).get("Contents", [])
        body = client.get_object(Bucket=bucket, Key=key)["Body"].read()
        print(f"objects at that key after two writes: {len(listed)} (want 1)")
        print(f"body holds: {body.decode()} (want second-write)")

        # 3. A refusal is a refusal.
        refused = S3ObjectStore(bucket=f"{bucket}-does-not-exist-{run}", region=region)
        try:
            await refused.put(SOURCE, partition, b"should not land")
            print("a write to a bucket that does not exist SUCCEEDED -- investigate")
        except Exception as exc:  # the type it raises is itself the finding
            print(f"a write that cannot succeed raises: {type(exc).__name__}")
    finally:
        if "--keep" in sys.argv:
            print(f"left behind: s3://{bucket}/{key}")
        else:
            client.delete_object(Bucket=bucket, Key=key)
            print("cleaned up")

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
