# SPEC: Okta System Log → OCSF → Amazon Security Lake

**Status:** v1 design, pinned to vendor docs verified 2026-09-02; §2.1, §2.2,
§2.6 and the `limit` bound in §2.3 checked again 2026-09-11.
**Scope discipline:** one source, one sink, end to end. The plugin seam is visible
but not generalized. Second sink and second source come after v1 ships.

---

## 1. What this is

A connector that reads the Okta System Log, normalizes each event into the Open
Cybersecurity Schema Framework (OCSF), and writes OCSF Parquet into an Amazon
Security Lake custom source.

The claim it exists to prove is narrow and deliberate: **security data is moved
between two systems correctly**, under the failure modes that actually occur —
restarts, rate limits, out-of-order delivery, and schema drift on both ends.

Everything below that is marked **[verified]** is quoted or derived from vendor
documentation, with the source and the date it was checked listed in §8.
Anything not marked verified is a design decision made here, not a fact about a
vendor.

---

## 2. The source: Okta System Log

Endpoint: `GET /api/v1/logs`

### 2.1 Two query modes, and why the distinction is the whole design

**[verified]** The API has two distinct modes, and they have different ordering
guarantees:

| | Polling query | Bounded query |
|---|---|---|
| Parameters | `since`, **no `until`**, `sortOrder=ASCENDING` | both `since` and `until` |
| Ordered by | internal **persistence** time | the `published` field |
| `next` link | **always present**, even when the page is empty | **absent on the last page** |
| Terminates | never — it is a stream | yes |
| Used for | tail mode | backfill mode |

**[verified]** A polling query "may return events out of order according to the
`published` field," because it is ordered by persistence time rather than
publication time. A bounded query is the reverse: its events "are guaranteed to be
in order according to the `published` field," but "not all events for the
specified time range may be present. Some events may be delayed. Such delays are
rare but possible." Okta states that caveat under bounded requests, not polling.
It is why a backfill range that ends near the present cannot be assumed complete,
and why the dedup set has to cover the overlap where backfill meets the tail
(§5.2).

**[verified]** The OpenAPI reference describes `sortOrder` as "the order of the
returned events that are sorted by the `published` property," with no polling
exception. Its `since` and `until` descriptions do draw the line ("persistence
time for polling queries"), and the query guide is explicit, so this document
follows the guide. Read alone, the `sortOrder` description suggests a timestamp
watermark is safe. It is not.

**This is the single most important fact in this document.** It means:

- `published` **cannot** be used as a resume watermark. An event with an earlier
  `published` may be persisted after one with a later `published`. A
  timestamp-based checkpoint silently drops those events forever.
- **[verified]** Okta states directly: "Don't transfer data by manually
  paginating using `since` and `until`, as this may lead to skipped or duplicated
  events. Instead, always follow the `next` links."

Therefore the checkpoint is **the opaque `next` cursor and nothing else**.
`published` is retained only as an observability signal (ingest lag), never as
control state.

### 2.2 Pagination

**[verified]** Pagination is via the `Link` response header with `rel="next"` and
`rel="self"`. The `after` parameter inside that link is "system generated for use
in `next` links. Don't attempt to craft requests that use this value."

So the connector persists the **entire next URL** verbatim, treats it as opaque,
and never parses or reconstructs it.

**[verified]** Okta's own documentation shows why verbatim has to mean
byte-for-byte. It states that "`since` and `after` are mutually exclusive and can't
be specified simultaneously," yet its sample `next` link carries both. A client
that tidied a `next` URL to match the stated rule would send a request Okta never
generated. Fixtures copy the documented shape, `since` included.

**What a cursor is, precisely.** A cursor is *the URL to GET next*. The source
builds the **opening** cursor — `/api/v1/logs?since=…&sortOrder=ASCENDING` for
tail, `since` + `until` for backfill — because a stream has to be opened somehow.
Every cursor after that is the `next` URL lifted verbatim from the `Link` header.

The opacity rule is therefore about `after`, not about the URL. The connector
never constructs or reads an `after`, and never derives a resume position from a
timestamp. Building the opening query from `since` violates neither: it is the
documented way to open a stream, and it cannot degrade into a resume path,
because the runner calls it only when the store holds no cursor
(`runner/loop.py`, §5). The opening `since` is load-bearing for a different
reason — see §5.2.

In tail mode, the `next` link is always present and the page may be empty. An
empty page is not an error and not an end-of-stream — it means "no new events
yet." The runner sleeps, then requests the `next` URL that the empty page
returned. Okta does not say whether that URL equals the one just requested, so
the runner does not assume it.

**Termination.** **[verified]** A bounded query has "a finite number of pages.
That is, the last page doesn't contain a `next` link relation header." That
absence is the only end-of-range signal: the runner ends a backfill on
`Page.next_cursor is None` and on nothing else. Okta does not say whether a
bounded query can return an empty page that still carries `next`; if one does,
the runner follows the link like any other page. The link decides, not the page
size.

**[verified]** Okta's export example says to "continue this process until no
events are returned." That example is `?since=…` with no `until`, and `sortOrder`
defaults to `ASCENDING`, so by Okta's own criteria it is a *polling* query, which
never ends. "No events" there means caught up — tail's idle condition. The
connector does not use it as a termination rule in either mode.

### 2.3 Rate limits

**[verified]** The `/api/v1/logs` bucket is **120 requests/minute org-wide**, and
a **single API token is capped at 60 requests/minute** against that endpoint.
Exceeding it returns HTTP 429. `X-Rate-Limit-Reset` carries the UTC epoch second
at which the limit resets; counters reset roughly every 60s but are not aligned
to wall-clock minutes. **[verified]** Individual queries time out at 30 seconds.

Design consequences:

- The binding constraint is the **per-token 60/min**, i.e. ~1 request/second
  sustained. Budget for that, not for the 120 org limit.
- On 429, sleep until `X-Rate-Limit-Reset` **plus jitter**, not a fixed backoff.
  Unjittered reset-time sleeps make every client in the org wake simultaneously.
- Proactively throttle on `X-Rate-Limit-Remaining` rather than waiting for the
  429. The connector shares the org budget with whatever else the customer runs.
- **[verified]** `limit` defaults to 100 and accepts an "Integer between 0 and
  1000". At ~1 request/second, page size is the throughput ceiling: about 6,000
  events/minute at the default, 60,000 at 1000. Okta's sample `next` link keeps
  the `limit` of the query that produced it, so the value is chosen once, in the
  opening query. On a stream that has committed, changing the configured `limit`
  has no effect, because resume follows the stored cursor; before the first
  commit it moves the opening cursor, which §5.2 shows is unsafe.

### 2.4 Authentication

**[verified]** For Okta-scoped management APIs, an OAuth 2.0 **service app** using
the **client credentials** grant with **`private_key_jwt`** is the *only*
supported client authentication method — client ID + secret is explicitly not
allowed. Required scope: `okta.logs.read`.

Design consequences:

- There is **no refresh token** in the client credentials flow. "Token refresh"
  here means minting a fresh signed JWT assertion and exchanging it for a new
  access token when the current one nears expiry. Renew on a margin (e.g. 80% of
  lifetime elapsed), not on 401.
- The private key is the credential. It is loaded from the environment or a
  secrets manager at startup and never read from a config file in the repo.
  Key rotation is supported by keying on the JWK `kid` so two keys can be valid
  during a rollover.

### 2.5 Event shape

Fields consumed from each log event: `uuid`, `published`, `eventType`,
`severity`, `displayMessage`, `actor`, `client`, `outcome`,
`authenticationContext`, `securityContext`, `target`, `transaction`,
`debugContext`.

`uuid` is the dedup key. `eventType` is the mapping key.

### 2.6 Retention

**[verified]** "System Log data older than 90 days isn't returned … Queries that
exceed the retention period succeed, but only those results that have a
`published` timestamp within the window are returned."

Retention loss is silent, and it reaches this connector two ways:

- An opening `since` older than 90 days opens without error at the edge of the
  window. Everything before that is gone, and nothing in the response says so.
- A stream left unconsumed for longer than the window resumes from a cursor
  whose events have aged out. Okta does not say whether a stale `after` still
  resolves; if it does, the runner resumes over a gap without error.

v1 detects neither yet. Both are checkable outside the response — the configured
`since` against the clock at startup, and the age of the last commit — and both
belong in §7 before v1 ships.

---

## 3. The normalization: OCSF

### 3.1 Version — and the constraint that decides it

**[verified]** The current released OCSF schema is **v1.9.0**.
**[verified]** Amazon Security Lake "supports OCSF version **1.3 and earlier**"
for custom sources.

The sink's schema ceiling is six minor versions below the spec. This is not a
detail to paper over; it is the versioning story:

- The mapper is **parameterized by target OCSF version**. v1 emits **1.3.0** for
  the Security Lake sink because that is the hard constraint.
- The version emitted is recorded in `metadata.version` on every event, and the
  mapping table carries its own independent version in
  `metadata.processed_time`-adjacent producer fields, so any record can be traced
  to the mapping revision that produced it.
- Future sinks (Splunk HEC, Datadog Logs) have no such ceiling and can take 1.9.

### 3.2 Class model

**[verified]** Identity & Access Management is `category_uid` **3**. Classes:

| class_uid | Class |
|---|---|
| 3001 | Account Change |
| 3002 | Authentication |
| 3003 | Authorize Session |
| 3004 | Entity Management |
| 3005 | User Access Management |
| 3006 | Group Management |
| 3007 | User Management |
| 3008 | Role Management |

**[verified]** `type_uid = class_uid * 100 + activity_id`.

**[verified]** Authentication (3002) `activity_id` values: 0 Unknown, 1 Logon,
2 Logoff, 3 Authentication Ticket, 4 Service Ticket Request, 5 Service Ticket
Renew, 6 Preauth, 7 Account Switch, 99 Other.

**[verified]** Authentication required attributes: `time`, `metadata`,
`category_uid`, `class_uid`, `type_uid`, `severity_id`, `status_id`,
`activity_id`, `user`. Recommended: `actor`, `src_endpoint`, `auth_protocol_id`,
`logon_type_id`, `session`, `is_mfa`, `message`, `status`, `observables`.
**[verified]** Constraint: at minimum either `dst_endpoint` **or** `service` must
be present — for Okta, populate `service` with the Okta org / application target.

### 3.3 Mapping is data, not code

Okta emits hundreds of `eventType` values and adds more continuously. The mapping
lives in `src/ocsf_connector/mapping/okta_ocsf.yaml` as a versioned table keyed by
`eventType`, not as a match statement.

Rules:

- An **unknown `eventType` must never crash or be dropped.** It falls back to a
  generic class with the full source event in `unmapped`, and increments an
  `unmapped_event_type` counter labeled by the event type. That counter is the
  early-warning signal for source-side drift.
- Every source field that is not mapped goes into `unmapped`. Populating
  `unmapped` honestly is a feature; silently discarding source fields is the
  signature of a toy connector.

Worked example — `user.session.start` → Authentication (3002), `activity_id` 1,
`type_uid` 300201:

| Okta field | OCSF target |
|---|---|
| `published` | `time` (epoch **milliseconds**, UTC) |
| `uuid` | `metadata.uid` |
| `published` | `metadata.original_time` (string, as received) |
| `outcome.result` SUCCESS / FAILURE | `status_id` 1 / 2 |
| `outcome.reason` | `status_detail` |
| `severity` INFO / WARN / ERROR | `severity_id` 1 / 3 / 4 |
| `actor.id` / `.displayName` / `.alternateId` | `actor.user.uid` / `.name` / `.email_addr` |
| `client.ipAddress` | `src_endpoint.ip` |
| `client.geographicalContext` | `src_endpoint.location` |
| `client.userAgent.rawUserAgent` | `http_request.user_agent` |
| `authenticationContext.authenticationStep`, MFA signals | `is_mfa`, `auth_protocol_id` |
| `target[]` | `service`, plus class-specific objects |
| `debugContext`, `securityContext`, `transaction` | `unmapped` |

---

## 4. The sink: Amazon Security Lake custom source

**[verified] requirements:**

- **Format:** Apache Parquet, one file per object. Parquet format versions 1.x
  and 2.x supported.
- **Compression:** **zstandard preferred.**
- **Layout:** data page ≤ **1 MB uncompressed**; row group ≤ **256 MB
  compressed**; records within an object **sorted by time**.
- **Partitioning:** objects must be prefixed
  `/ext/{custom-source-name}/region={region}/accountId={accountId}/eventDay={YYYYMMDD}/`,
  where `eventDay` is the UTC record timestamp as `YYYYMMDD`.
- **Object cadence:** files should be sent in increments between **5 minutes and
  1 event day**; more often than 5 minutes only if files exceed 256 MB.
- **One event class per object.** "The same OCSF event class should apply to each
  record within a Parquet-formatted object," and sources spanning multiple
  categories "should deliver each unique OCSF event class as a separate source."
- **Limit:** max **50 custom sources per account**.
- **[verified]** Registration creates: an IAM role named
  `AmazonSecurityLake-Provider-{source-name}-{region}` (permissions boundary
  `AmazonSecurityLakePermissionsBoundary`), a Lake Formation table, and a Glue
  crawler that populates the Data Catalog.

### 4.1 Design consequences

**The one-class-per-object rule shapes the writer.** A single Okta System Log
stream fans out across at least four OCSF classes (3001, 3002, 3003, 3004). The
sink therefore:

1. Buckets mapped events **by `class_uid`** before serialization.
2. Writes a separate Parquet object per (class, eventDay) pair.
3. Registers **one Security Lake custom source per OCSF class** — e.g.
   `okta_authentication`, `okta_account_change`. Well within the 50-source cap.

**`accountId` for a non-AWS source.** Okta events do not belong to an AWS
account. **[verified]** AWS recommends a string such as `external` or
`external_{externalAccountId}` for exactly this case. v1 uses
`external_{okta_org_id}`.

**Batching is a real tradeoff, not a knob.** The 5-minute floor is in direct
tension with the commit-after-ack rule in §5: a larger batch means fewer, better
Parquet objects but a longer window of un-acked work to replay after a crash. v1
flushes on whichever comes first — 5 minutes elapsed or 256 MB buffered — and
accepts the replay window, because dedup (§5) makes replay harmless.

---

## 5. Correctness: checkpointing, ordering, idempotency

The delivery guarantee is **at-least-once from the source, made effectively-once
at the sink by two different mechanisms that cover two different failure modes.**
Conflating them was an error in an earlier draft of this section; §5.2 is the
correction.

The commit order is fixed and is the core invariant of this connector:

```
fetch page  →  map  →  dedup  →  buffer  →  flush to sink  →  sink ACKs  →  THEN commit cursor
```

- Persisting the cursor **before** the sink acknowledges loses events on crash.
- Never persisting re-ingests the world on every restart.
- Persisting **after** the ack means a crash in the gap replays the last batch.

It lives in exactly one place in the code, `runner/loop.py`, which tail and
backfill share.

### 5.1 The commit is atomic, and dedup runs after mapping

**The cursor and the seen-set advance together, in one `commit()`.** Two separate
calls would open a third crash window between them. Both orderings of those two
calls happen to be recoverable, but that is an argument to re-derive at every
change; one atomic call makes it structural. A durable store must land both
writes in a single transaction or it has not implemented `StateStore`.

**Dedup runs after mapping, not before.** Filtering first would save work on
duplicates, but mapping every record — including one already delivered — is what
keeps `unmapped_event_type_total` incrementing on replay. Filtering first means a
newly-appeared unknown `eventType` goes quiet the moment it repeats, which is
precisely when the drift alarm should be loudest. Mapping is total (§3.3), so
mapping a duplicate cannot fail.

### 5.2 What dedup actually covers, and what covers the rest

The `uuid` seen-set does **not** absorb a crash in the ack→commit gap. Because
the commit is atomic, the crash that loses the cursor loses the seen-set in the
same instant; the replayed batch arrives looking entirely new. The seen-set
covers a different, real problem: **duplicates the source delivers**, which Okta
documents ("may lead to skipped or duplicated events", §2.1), plus the overlap
where a backfill range meets the tail.

Exactly-once across a crash rests instead on **the sink write being idempotent**:

- A batch is addressed by a `batch_key` — **the cursor the batch began at**.
- `Sink.flush(batch_key)` writes the buffer to an object derived from that key,
  so a replayed batch **overwrites** its object instead of adding a second one.
- The key is stable across replay because the runner resumes from that same
  cursor and the vendor returns the same page for it.
- `should_flush` is read only at page boundaries, so a batch is always a whole
  number of pages. If a replayed batch covers *fewer* pages than the original,
  the events it drops are picked up by the batch starting where it ended — so
  differing batch boundaries are self-healing, not a leak.

**The first batch is the exception, and it is the caller's to close.** Before the
first commit there is no stored cursor, so the batch is keyed by whatever the
opening query resolved to (§2.2). Crash in that first ack→commit gap and the
runner restarts with the store still empty, opens the stream again, and addresses
the replayed batch by the *new* opening URL — a second object, not an overwrite.
The opening cursor must therefore be stable across restarts, which means tail's
`since` comes from configuration or a persisted stream origin and **never from
`now()`**. The runner cannot enforce this; it has no way to know how `start()`
computed its answer. It is an obligation on the mode entry point (§6), and
`tests/test_commit_order.py` pins both halves — that a stable origin replays into
one object, and that a moving one does not.

The consequence for §4: object naming is not a cosmetic choice. `batch_key` is
an opaque cursor and must be escaped or hashed before it becomes a path segment.

### 5.3 State store contents

| Key | Purpose |
|---|---|
| `cursor` | the opaque `next` URL, verbatim. The only resume control state. `None` after a bounded range completes, which a store must distinguish from "never started". |
| `seen_uuids` | bounded set of recently-seen event `uuid`s, TTL'd by wall clock (default 24h). Covers source-side duplicates, **not** crash replay. |
| `last_published` | most recent `published` seen. **Observability only.** Never used to resume. |
| `mapping_version` | mapping table revision that produced the last committed batch. Written with the cursor; read on startup to detect that the table moved under a resumed stream. |

### 5.4 The tests that matter

`tests/test_commit_order.py` kills the runner in the ack→commit gap, restarts it
against the same durable state, and asserts every `uuid` lands exactly once —
plus that a sink failure never advances the cursor, and that a replayed batch
overwrites its object rather than adding one. Two more cover the first batch,
which has no stored cursor behind it: a stable opening cursor replays into one
object, and a moving one does not (§5.2). Inverting the commit order in
`runner/loop.py` fails five of them, and making `batch_key` unstable fails four;
a test that cannot fail is not evidence.
That suite, more than any other artifact in this repo, is the thing worth
pointing a buyer at.

---

## 6. Modes

**Tail** — polling query (`sortOrder=ASCENDING`, no `until`), resumes from the
stored cursor, follows `next` forever, sleeps on empty pages, respects the
per-token 60/min budget. Its opening `since` — read only when the store holds no
cursor — comes from configuration or a persisted stream origin, **never from
`now()` at startup**. That is a correctness constraint, not a preference: §5.2
shows the duplicate object it prevents.

**Backfill** — bounded query (`since` + `until`), paginates until `next` is
absent, then exits. Shares the mapper, sink, state store, and dedup set with tail
mode; only the fetch loop and termination condition differ.

Both modes write through the identical mapping and sink path. If backfill and
tail ever produce different OCSF output for the same source event, that is a bug,
and there is a test asserting they do not.

---

## 7. Self-observability

Emitted as OpenTelemetry metrics:

| Metric | Why it exists |
|---|---|
| `ingest_lag_seconds` | `now − published`. The headline SLI. Uses `published` for the one purpose it is safe for. |
| `events_per_second` | throughput |
| `error_rate` by class | source vs. map vs. sink failures, separated |
| `unmapped_event_type_total{event_type}` | source schema drift early warning |
| `rate_limit_remaining` | headroom against the shared org budget |
| `cursor_commit_lag_seconds` | how much work is at risk of replay right now |
| `parquet_objects_written{class_uid}` | sink health per Security Lake source |

---

## 8. Sources verified 2026-09-02

- [Okta — System Log query](https://developer.okta.com/docs/reference/system-log-query/) — polling vs bounded, ordering, `next` links, `after`, delayed events; termination, retention, the export example (checked again 2026-09-11)
- [Okta — Rate limits](https://developer.okta.com/docs/reference/rate-limits/) — `/api/v1/logs` 120/min org, 60/min per token
- [Okta — Implement OAuth for Okta with a service app](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/) — client credentials + `private_key_jwt` only
- [Okta — System Log API](https://developer.okta.com/docs/api/openapi/okta-management/management/tags/systemlog) — renders client-side; read from its source, below
- [Okta — Management OpenAPI spec, `dist/2026.08.4/management-minimal.yaml`](https://github.com/okta/okta-management-openapi-spec/blob/master/dist/2026.08.4/management-minimal.yaml) — `listLogEvents`: `limit` 0–1000 default 100, `sortOrder` default `ASCENDING`, `sortOrder` wording (checked 2026-09-11)
- [OCSF schema browser](https://schema.ocsf.io/) — v1.9.0, IAM category 3, class UIDs
- [OCSF — Authentication (3002)](https://schema.ocsf.io/1.9.0/classes/authentication) — activity IDs, required attributes, `type_uid` formula
- [AWS — Collecting data from custom sources in Security Lake](https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html) — OCSF 1.3 ceiling, Parquet/zstd, partitioning, one class per object

Re-verify §2 and §4 before v1 ships. Both vendors change these pages.

---

## 9. Explicitly out of scope for v1

Splunk HEC and Datadog Logs sinks. Tailscale as a second source. A generalized
plugin registry or entry-point loader. Multi-tenant orchestration. A UI.

A narrow tool that works reads better than a half-finished framework.
