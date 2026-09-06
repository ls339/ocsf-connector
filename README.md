# ocsf-connector

Ships Okta System Log events into Amazon Security Lake as OCSF Parquet.

Status: **in development.** v1 target is Okta → OCSF 1.3 → Security Lake custom
source, tail and backfill.

---

## Why this exists, and what is actually hard about it

Reading a log API and writing JSON is a weekend script. The reason connectors
take real engineering is what happens at the edges, and this repo is organized
around three of them.

**1. You cannot resume from a timestamp.**

Okta's System Log has two query modes. A *bounded* query (`since` + `until`) is
ordered by the event's `published` field. A *polling* query (`since`, no `until`,
`sortOrder=ASCENDING`) is ordered by Okta's **internal persistence time**, and
Okta documents that it "may return events out of order according to the
`published` field."

So an event stamped 10:00:00 can arrive after one stamped 10:00:05. Any connector
that checkpoints `max(published)` and resumes from there drops the late one, in
production, permanently, without an error. Okta says it plainly: *"Don't transfer
data by manually paginating using `since` and `until`, as this may lead to skipped
or duplicated events."*

This connector persists the opaque `next` cursor and nothing else. `published` is
used for exactly one thing: computing ingest lag.

**2. The commit order is the delivery guarantee.**

```
fetch → map → buffer → flush to sink → sink ACKs → THEN persist cursor
```

Commit before the ack and a crash loses the batch. Never commit and every restart
re-ingests the world. Commit after, and a crash in the gap replays the last batch
— which a TTL'd set of recently-seen event `uuid`s absorbs. At-least-once
delivery plus dedup is effectively-once at the sink.

The test worth reading is the one that kills the process inside that gap and
asserts each `uuid` lands exactly once.

**3. The sink's schema ceiling is below the spec's.**

OCSF is at 1.9.0. Amazon Security Lake accepts **1.3 and earlier** from custom
sources. So the mapper is parameterized by target OCSF version rather than
hardcoding the current one, and every record carries both the OCSF version and
the mapping-table revision that produced it.

Security Lake also requires **one OCSF class per Parquet object**, while a single
Okta stream fans out across Authentication, Account Change, Authorize Session and
Entity Management. The sink buckets by `class_uid` and registers one custom
source per class.

---

## Design

Full design and the vendor facts it rests on: **[`docs/SPEC.md`](docs/SPEC.md)**.
Every vendor behavior asserted there is marked `[verified]` and linked to the
documentation page it came from, with the date it was checked.

## Layout

```
src/ocsf_connector/
  sources/okta/     auth (private_key_jwt), fetch, cursor handling
  mapping/          okta_ocsf.yaml + version-parameterized mapper
  sinks/            OCSF Parquet writer, Security Lake partition layout
  state/            cursor + dedup store
  runner/           tail and backfill
  telemetry/        ingest lag, error rate, unmapped-type drift
tests/fixtures/     recorded API pages -- all synthetic
terraform/          Security Lake custom source registration
```

## Data handling

All fixtures are synthetic. No real tenant id, user, email address, or IP address
appears anywhere in this repository.
