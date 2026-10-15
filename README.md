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
re-ingests the world. Commit after, and a crash in the gap replays the last batch.

The replay is *not* caught by the dedup set — the cursor and the seen-set are
committed atomically, so the crash that loses one loses the other, and the
replayed batch arrives looking new. It is caught by making the write idempotent:
a batch is addressed by the cursor it began at, so re-flushing overwrites its
object instead of adding a second one. The TTL'd `uuid` set covers a different
failure — duplicates Okta itself delivers. Two mechanisms, two failure modes;
`docs/SPEC.md` §5.2 is explicit about which covers what, because an earlier draft
of that section was not.

The tests worth reading are in `tests/test_commit_order.py`: they kill the runner
inside that gap and assert each `uuid` lands exactly once. Inverting the commit
order fails five of them; making the batch key unstable fails four.

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

## Running it

```sh
cp config.example.toml config.toml     # then set org, client id, key path, since
uv run ocsf-connector tail
uv run ocsf-connector backfill --since 2026-09-01T00:00:00Z --until 2026-09-02T00:00:00Z
```

Set `kind = "s3"` and a `bucket` to deliver; the default writes Parquet into
`out/` instead, laid out exactly as it would be in the bucket so a partition
mistake is visible in a directory tree.

`tail` follows the stream forever and resumes from the committed cursor. `backfill`
walks a closed range and exits. They run under different stream names on purpose,
so a backfill cannot overwrite the tail's resume position, and they share the dedup
set, so the overlap where a backfill meets the tail does not duplicate events.

Either mode stops on `SIGINT` (Ctrl-C) or `SIGTERM` (what a container runtime
sends): it finishes the page it is on, prints what the run did, and exits 130 or
143. A second signal cancels instead of waiting. A tail also prints one `alive:`
line every five minutes, because a healthy idle tail commits nothing and would
otherwise be indistinguishable from a wedged one.

Secrets are named, never stored: the config file holds a *path* to the PEM private
key. Any setting can be overridden from the environment — the full list of
variables is one table in `src/ocsf_connector/config.py`.

**Verified end to end, 2026-10-12.** 402 Okta events read over a DPoP-authenticated
connection, normalised to OCSF 1.3, written as Parquet by a role scoped to a single
custom source, encrypted with a customer-managed key, catalogued by Glue, and
returned by an Athena query — which read 0.70 KB to do it. The mapping decisions
survive the round trip: MFA events arrive as activity 6 Preauth rather than 1
Logon, so a count of logons is a count of logons.

## Deploying it

The connector is one long-lived process: `tail` is a service, `backfill` is a job.
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) is the detail;
`deploy/ecs/task-definition.json` and `deploy/kubernetes/statefulset.yaml` are
working starting points.

**Run exactly one replica.** This is the one deployment mistake that costs data
rather than uptime. The cursor and dedup set are SQLite on a volume, so two
replicas keep separate cursors, derive different batch keys from the same events,
and write duplicate objects into the lake — silently, because the idempotent
overwrite only holds for a replay of the *same* key. On ECS that means
`minimumHealthyPercent=0` as well as `desiredCount=1`, or a routine deployment
runs two tails for a few seconds. On Kubernetes it means a StatefulSet rather
than a Deployment.

Scaling up would not help anyway: the throughput ceiling is Okta's rate limit on
a single ordered cursor, which no amount of parallelism raises.

The published image carries **no configuration file** — baking one in would put
a tenant's org URL and client id inside a shared image — so a container takes
every setting from the environment, and the platform injects the keys as
environment entries. The connector never reads a secret store itself, which is
why its AWS access is `sts:AssumeRole` on seven roles and nothing else.

**Verified on ECS Fargate, 2026-10-14.** A 0.25 vCPU / 0.5 GB ARM64 task, state
on an EFS access point with transit encryption and IAM authorization, delivering
Parquet to a registered Security Lake custom source through per-source provider
roles. Run in both network shapes: a private subnet behind a NAT gateway, and a
public subnet with no inbound rules — the task listens on nothing either way, and
a dedicated NAT costs more per month than the compute it serves. `SIGTERM` from the orchestrator finished the
page in flight, flushed, committed, printed its summary and exited 143; the
replacement task resumed from that cursor and read 2 new events rather than
re-reading 413.

**What is still unproven.** One property, and neither a test nor an idle service
can reach it: the store assumes each provider role and renews the credentials at
80% of their lifetime, so an hour-long session renews at 48 minutes. A laptop run
never gets there and a fixture cannot age. Uptime alone does not do it either —
the roles are assumed at flush time, so proving renewal needs two flushes more
than 48 minutes apart, which means a stream with events still arriving an hour
in. A quiet org idles past the boundary without ever testing it.

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
terraform/
  log-archive/      Security Lake custom sources, one per class, and the crawler role
  security-tooling/ the role the connector runs as, and its one privilege
deploy/
  ecs/              Fargate task definition
  kubernetes/       StatefulSet -- one replica, and the comments explain why
```

Note what `terraform/` does *not* contain: no VPC, no cluster, no node group.
Those belong to the environment the connector runs in, and an integration that
creates an enterprise's network is an integration nobody installs.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Permissive, with an explicit
patent grant, which is the form corporate review usually expects.

## Data handling

All fixtures are synthetic. No real tenant id, user, email address, or IP address
appears anywhere in this repository.
