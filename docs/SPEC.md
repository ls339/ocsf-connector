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

**Reading `next`, and where a cursor may point.** The `next` cursor is the exact
text between the angle brackets of the `rel="next"` link-value. A generic `Link`
parser is not good enough — httpx's `Response.links`, for one, splits a URL that
contains `;`. Before any GET, the source checks one thing about a cursor: that it
begins with the configured org's `https://…/api/v1/logs?`. That reads no
parameter and derives no position; it keeps the bearer token on this org's logs
endpoint if a state store ever hands back something else. It assumes Okta's
`next` links use the host the request was sent to. The pages in §8 do not state
that, and it is the first thing to confirm against a live org — custom domains
especially. The DPoP proof's `htu` splits the same URL at the `?` (§2.4); those
two are the only reads of a cursor's text anywhere in the connector.

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

**[verified]** A client gets **half a bucket by default**: "each API token or
OAuth 2.0 app can use up to 50% of a bucket's total rate limit." Okta illustrates
the rule with this very endpoint — "if your org-wide limit for the `/api/v1/logs`
bucket is 120 requests per minute, a single API token can only make 60 requests
per minute."

**That 120 is Okta's example, not a published constant**, and an earlier draft of
this section quoted it as though it were one. Okta prints no per-endpoint table:
a bucket's quota "can vary based on … the type of service subscription …, the
HTTP method used, the number of licenses purchased, and any applicable add-ons",
and on whether the org is an Integrator Free Plan org. The authoritative number
for a given org is in the Admin Console under **Reports → Rate Limits**.

Exceeding a quota returns HTTP 429. `X-Rate-Limit-Reset` carries the UTC epoch
second at which the limit resets; counters reset roughly every 60s but are not
aligned to wall-clock minutes. **[verified]** Individual queries time out at 30
seconds.

Design consequences:

- **The connector must not hardcode a quota, and does not.** It budgets from the
  headers on each response — `X-Rate-Limit-Remaining` and `X-Rate-Limit-Reset` —
  which are the only figures true for the org it is actually pointed at. Size
  capacity planning at roughly ~1 request/second and confirm against the
  dashboard; a free-plan org and a licensed one need not agree.
- On 429, sleep until `X-Rate-Limit-Reset` **plus jitter**, not a fixed backoff.
  Unjittered reset-time sleeps make every client in the org wake simultaneously.
- Proactively throttle on `X-Rate-Limit-Remaining` rather than waiting for the
  429. The connector shares the org budget with whatever else the customer runs.
- **[verified]** The 50% share is adjustable, not fixed: "By default, all new
  apps consume 50% of every API's rate limits", movable per app in the Admin
  Console or through the principal rate limits API. An admin can lower it, and
  whatever remains of the bucket is shared with everything else the customer
  runs — which is the argument for throttling early rather than at the 429.
- **[verified]** `limit` defaults to 100 and accepts an "Integer between 0 and
  1000". At ~1 request/second, page size is the throughput ceiling: about 6,000
  events/minute at the default, 60,000 at 1000. Okta's sample `next` link keeps
  the `limit` of the query that produced it, so the value is chosen once, in the
  opening query — v1 chooses 1000. On a stream that has committed, changing the
  configured `limit` has no effect, because resume follows the stored cursor;
  before the first commit it moves the opening cursor, which §5.2 shows is
  unsafe.

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

**[verified] The token request.** POST to the **org** authorization server at
`https://{yourOktaDomain}/oauth2/v1/token` — not `/oauth2/default` — form
encoded: `grant_type=client_credentials`, `scope` (space separated),
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`,
`client_assertion`. The assertion carries `iss` = `sub` = client ID and `aud` =
that token URL, and Okta rejects an `exp` "more than one hour in the future".
`jti` is optional and makes the assertion single-use, so a fresh one is minted
per request. The signing `alg` — RS256/384/512 or ES256/384/512 — belongs in the
JWT header, with `kid` naming the registered key. The response is `token_type`
`Bearer`, `expires_in` 3600, and the lifetime is "fixed at one hour."

**[verified] DPoP changes the shape of every request.** A service app can require
Demonstrating Proof-of-Possession, and **it is on by default**. This was an
inference from Okta's own walkthrough telling the reader to *turn it off* on a
newly created API Services app; on 2026-09-16 a freshly created Integrator Free
Plan app required it without anyone enabling it, which settles the question. No
Okta page states the default outright. With it on:

- The DPoP key pair is **separate** from the client-authentication key pair.
- The token POST carries a `DPoP` proof: header `typ` `dpop+jwt`, an asymmetric
  `alg`, and the **public** JWK; payload `htm`, `htu`, `iat`. Okta refuses the
  first one with `400 use_dpop_nonce` and a `dpop-nonce` header; the retry adds
  that `nonce` and a `jti`. The nonce is renewed every 24 hours and the previous
  value keeps working for three days, so it is cached rather than re-fetched.
- The response is `token_type` `DPoP`, and every API request then needs
  `Authorization: DPoP {token}` plus a **fresh** proof carrying `ath` (base64url
  SHA-256 of the token), `htm`, `htu`, `iat`, `jti`. Okta says the nonce "isn't
  currently required" in that proof.

v1 speaks both. A Bearer-only connector would ask the customer to weaken their
app to run it, which is a poor trade in a tool whose subject is security data.
The seam is therefore per request — `Authorizer.headers(method, url)` — because
a proof commits to one method and one URL and may not be replayed on a retry. The
returned `token_type` is checked against the configured mode, so an app whose
DPoP setting disagrees with the config fails with a message naming the fix.

**[verified]** RFC 9449 §4.2 defines `htu` as the target URI "without query and
fragment parts". For a cursor that means everything before the `?` — with the
origin check in §2.2, one of exactly two places this connector reads a cursor's
text, and like that one it reads no parameter.

### 2.5 Event shape

An earlier version of this list named fields the mapping never touched and
omitted three the vendor actually sends. What follows is what the code does,
in three groups, because the distinction is the thing that keeps `unmapped`
honest.

**Fully consumed.** `uuid` — the dedup key, and `metadata.uid`. `published` —
`time` (epoch ms) and `metadata.original_time` (verbatim). `eventType` — the
mapping key, so it picks `class_uid` and `activity_id`, and rides along as
`metadata.event_code`. `severity`, `displayMessage`, `outcome`.

**Partially consumed; the remainder is preserved.** `actor` (`id`,
`displayName`, `alternateId` are mapped, `type` and `detailEntry` are not);
`client` (`ipAddress`, `geographicalContext`, `userAgent.rawUserAgent` are
mapped, `zone`, `device`, `id` and the parsed user-agent fields are not);
`authenticationContext` (the session id and the MFA signals are mapped, the rest
is not).

**Not consumed at all.** `target` — read to build the class-specific object but
deliberately never *marked* consumed, because an event can name several targets
and a class has room for one (§3.3) — plus `transaction`, `debugContext`,
`securityContext`, `request` (the proxy `ipChain`), `version`, and
`legacyEventType`.

Everything in the last two groups lands under `unmapped`; nothing is dropped.
"Consumed" means marked consumed by the reader as it maps, which is what lets
`unmapped` be computed rather than maintained as a hand-written exclusion list
that would drift the first time a field moved.

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
  mapping table's own revision rides in `metadata.labels` as
  `okta-ocsf-mapping:{version}`, so any record can be traced to the rules that
  produced it.
- Future sinks (Splunk HEC, Datadog Logs) have no such ceiling and can take 1.9.

### 3.2 Class model

**[verified]** Identity & Access Management is `category_uid` **3**. These are the
classes **OCSF 1.3.0** defines — the version this connector emits (§3.1). 1.9.0
adds User Management (3007) and Role Management (3008), which do not exist in
1.3.0; the mapping table may not name them.

| class_uid | Class | Required beyond the base event | Constraint |
|---|---|---|---|
| 3001 | Account Change | `user` | — |
| 3002 | Authentication | `user` | at least one of `service`, `dst_endpoint` |
| 3003 | Authorize Session | `user` | exactly one of `privileges`, `group` |
| 3004 | Entity Management | `entity` | — |
| 3005 | User Access Management | `user`, `privileges` | — |
| 3006 | Group Management | `group` | at least one of `privileges`, `user` |

**[verified]** `type_uid = class_uid * 100 + activity_id`, computed by the
producer. Base Event is `class_uid` **0** in `category_uid` **0**, and it is
emittable in its own right — which is what §3.3's fallback rests on.

**[verified]** Every class above also requires the base event's `activity_id`,
`category_uid`, `class_uid`, `metadata`, `severity_id`, `time` and `type_uid`.
`status_id` is only **recommended** in 1.3.0, and `unmapped` is optional.

**[verified] Two required-looking attributes are not required.** The schema shows
`cloud` and `osint` as required on every class, but both belong to opt-in
**profiles** of the same names. This connector enables no profiles and emits
neither. Reading a requirement without its profile is the trap here.

**[verified]** Authentication (3002) `activity_id`: 0 Unknown, 1 Logon, 2 Logoff,
3 Authentication Ticket, 4 Service Ticket Request, 5 Service Ticket Renew,
6 Preauth, 99 Other. **1.3.0 has no 7 Account Switch** — that arrives in a later
version, and a table naming it emits records the target version rejects.

**[verified]** The other enums the table draws on, each also carrying 0 Unknown
and 99 Other: Account Change (3001) 1 Create, 2 Enable, 3 Password Change,
4 Password Reset, 5 Disable, 6 Delete, 7 Attach Policy, 8 Detach Policy, 9 Lock,
10 MFA Factor Enable, 11 MFA Factor Disable; Authorize Session (3003) 1 Assign
Privileges, 2 Assign Groups; Entity Management (3004) 1 Create, 2 Read, 3 Update,
4 Delete, 5 Move, 6 Enroll, 7 Unenroll, 8 Enable, 9 Disable, 10 Activate,
11 Deactivate, 12 Suspend, 13 Resume; User Access (3005) 1 Assign Privileges,
2 Revoke Privileges; Group Management (3006) 1 Assign Privileges, 2 Revoke
Privileges, 3 Add User, 4 Remove User, 5 Delete, 6 Create.

**[verified]** `status_id`: 0 Unknown, 1 Success, 2 Failure, 99 Other.
`severity_id`: 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical,
6 Fatal, 99 Other.

**Which attributes a class has is not uniform**, so the mapper checks instead of
assuming: only Authentication defines `service`, `session` and `is_mfa`; Entity
Management defines `entity` and no `user`; `http_request` is optional but present
on all six. An attribute the class does not define makes the record invalid for
that class, so every event is filtered against a per-class set in
`mapping/okta.py`.

### 3.3 Mapping is data, not code

Okta emits hundreds of `eventType` values and adds more continuously. The mapping
lives in `src/ocsf_connector/mapping/okta_ocsf.yaml` as a versioned table keyed by
`eventType`, not as a match statement.

Rules:

- An **unknown `eventType` must never crash or be dropped.** It falls back to
  **Base Event** — `class_uid` 0, `category_uid` 0, `activity_id` 0 Unknown —
  with the full source event in `unmapped`, and increments an
  `unmapped_event_type` counter labeled by the event type. That counter is the
  early-warning signal for source-side drift, so it counts every occurrence, not
  just the first. Base Event rather than a nearby IAM class because 1.3.0's IAM
  category has no generic member, and guessing a class is how a connector
  quietly mislabels security data.
- **`published` is an ISO 8601 string; OCSF `time` is epoch milliseconds.** A
  timestamp that will not parse yields `0` rather than an exception, and the
  original string is kept in `metadata.original_time` either way.
- The table is seeded from the event types Okta documents. It is not exhaustive
  and is not meant to be — Okta adds types continuously, which is the whole
  reason the fallback and the counter exist.
- Every source field that is not mapped goes into `unmapped`. Populating
  `unmapped` honestly is a feature; silently discarding source fields is the
  signature of a toy connector.

Worked example — `user.session.start` → Authentication (3002), `activity_id` 1,
`type_uid` 300201:

| Okta field | OCSF target |
|---|---|
| `published` | `time` (epoch **milliseconds**, UTC) |
| `uuid` | `metadata.uid` |
| `eventType` | the class and activity, and `metadata.event_code` |
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

**The Parquet schema is half declared, half inferred, and that is a decision.**
It becomes the Glue table that Athena queries bind to, so changing it later means
rewriting published objects.

- The **base-event columns** every OCSF record carries — `time`, `class_uid`,
  `category_uid`, `activity_id`, `type_uid`, `severity_id`, `status_id`,
  `status`, `status_detail`, `message`, `metadata` — are declared with fixed
  Arrow types in `sinks/security_lake.py`. Identical in every object, whatever
  the class, so the table's core cannot drift.
- **Class-specific objects** (`user`, `entity`, `service`, `group`,
  `privileges`, `session`, `is_mfa`, `src_endpoint`, `http_request`) are inferred
  per batch. The six IAM classes do not agree on which of these exist (§3.2), and
  pinning all of them by hand would make every newly mapped field a schema edit.
- **`unmapped` is a JSON string.** Its shape is by definition whatever the vendor
  sent, which is not something a column type can describe.
- A column that is null for every row in an object is **dropped**, because an
  inferred all-null column takes Arrow's `null` type and reaches the Glue table
  as something no query can use.

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

**The durable implementation.** `state/sqlite.py` is the one that has to earn
this: one file, two tables, and `commit()` as a single `BEGIN IMMEDIATE … COMMIT`
so the cursor row and the seen rows land together or not at all. A `committed`
column, not `cursor IS NULL`, separates a finished range from a stream that never
started.

- **WAL plus `synchronous=FULL`.** A commit that has not reached the disk is a
  lie about what the sink acknowledged, and the entire guarantee is that the
  commit *follows* the ack. It costs one fsync per flushed batch, not per event.
- **One transaction at a time.** `sqlite3.threadsafety` is 3, so the connection
  may be shared across threads, but a connection holds one transaction: two
  overlapping `BEGIN IMMEDIATE` calls raise "cannot start a transaction within a
  transaction". Every transaction therefore runs under an `asyncio.Lock`.
- **Wall clock, not monotonic.** The in-memory store defaults to
  `time.monotonic`, which is correct when state dies with the process. A TTL that
  outlives the process cannot use it: monotonic clocks restart when the process
  does.

The commit-order suite (§5.4) runs against both stores. In the durable run a
restart closes the connection and reopens the file — which is the difference
between asserting atomicity and demonstrating it.

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
and `tests/test_end_to_end.py` asserts they do not.

**They must not share a stream name.** The state store is keyed by stream (§5.3),
so a backfill running under tail's name would overwrite tail's resume position
with the end of a closed range. The entry points default to `okta-tail` and
`okta-backfill`, overridable in configuration. The dedup seen-set is deliberately
*not* per stream, which is what keeps the overlap harmless where a backfill range
meets the tail (§5.2).

**The command line enforces what the runner cannot.** `ocsf-connector tail` takes
no time bounds at all, because the opening `since` comes from configuration and a
flag invites `--since $(date)` — the moving opening cursor §5.2 exists to prevent.
`ocsf-connector backfill` requires both `--since` and `--until`, since a bounded
query is meaningless without them. A parser refuses those mistakes; a runtime
check only reports them afterwards.

---

## 7. Self-observability

Emitted as OpenTelemetry metrics:

| Metric | Why it exists |
|---|---|
| `ingest_lag_seconds` | `now − published`. The headline SLI. Uses `published` for the one purpose it is safe for. |
| `events_total{stream}` | throughput — see below |
| `errors_total{stage,stream}` | source vs. map vs. sink failures, separated |
| `unmapped_event_type_total{event_type}` | source schema drift early warning |
| `rate_limit_remaining` | headroom against the shared org budget |
| `cursor_commit_lag_seconds` | how much work is at risk of replay right now |
| `parquet_objects_written{class_uid}` | sink health per Security Lake source |

**Counters, not rates.** SPEC once named two of these as rates. A rate computed
in-process is wrong the moment there is more than one instance, and wrong again
across a restart, because the divisor is whatever window that process happened to
see. The connector emits monotonic counters and lets whatever scrapes them divide
over the window the viewer asked for. Lags are histograms for the same reason: a
p99 across a fleet cannot be rebuilt from the last value each instance held.

**Where each signal comes from.** The source reports rate-limit headroom, being
the only thing that sees those headers (§2.3); the mapper's existing drift hook
feeds `unmapped_event_type_total` (§3.3); the sink counts objects per class,
because Security Lake registers one source per class and a single number would
hide a dead one (§4.1); the runner reports throughput, both lags, and errors by
stage. Only `telemetry/` imports OpenTelemetry, and the default implementation is
silent — this connector must never require an observability stack in order to run.

**No telemetry call may sit between the sink's acknowledgement and the cursor
commit.** That gap is the delivery guarantee (§5), and a metrics backend having a
bad day must not be able to strand an acknowledged batch behind an uncommitted
cursor. Commit lag is recorded *after* the commit returns, and the test for it
makes the metrics call raise, then asserts the cursor committed anyway.

---

## 8. Sources verified 2026-09-02

- [Okta — System Log query](https://developer.okta.com/docs/reference/system-log-query/) — polling vs bounded, ordering, `next` links, `after`, delayed events; termination, retention, the export example (checked again 2026-09-11)
- [Okta — Rate limits overview](https://developer.okta.com/docs/reference/rate-limits/) — buckets and scopes; a quota varies by subscription type, HTTP method, licenses, add-ons, and Integrator Free Plan status (re-checked 2026-09-14: the per-endpoint numbers this document once cited as fact are no longer published here, if they ever were)
- [Okta — Token and OAuth 2.0 app rate limits](https://developer.okta.com/docs/reference/rl2-token-oauth/) — a token or app gets 50% of a bucket by default, illustrated with `/api/v1/logs` at 120/min org and 60/min per token (checked 2026-09-14)
- [Okta — Monitor and troubleshoot rate limits](https://developer.okta.com/docs/reference/rl2-monitor/) — the Rate Limits dashboard, Reports → Rate Limits, where a given org's real bucket quota is visible (checked 2026-09-14)
- [Okta — Implement OAuth for Okta with a service app](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/main/) — client credentials + `private_key_jwt` only; token endpoint, assertion claims, `token_type` Bearer / `expires_in` 3600 (checked 2026-09-11)
- [Okta — Build a JWT for client authentication](https://developer.okta.com/docs/guides/build-self-signed-jwt/java/main/) — assertion claim table: `aud`, `exp` ≤ 1h, `iss`, `sub`, optional single-use `jti` (checked 2026-09-11)
- [Okta — Configure OAuth 2.0 Demonstrating Proof-of-Possession (Okta resource server)](https://developer.okta.com/docs/guides/dpop/oktaresourceserver/main/) — proof claims, nonce handshake, `ath`, `Authorization: DPoP` (checked 2026-09-11)
- [Okta — How to Build Secure Okta Node.js Integrations with DPoP](https://developer.okta.com/blog/2024/10/23/dpop-oauth-node) — the walkthrough that disables Require DPoP on a new API Services app (checked 2026-09-11)
- [Okta — Create OIDC app integrations](https://help.okta.com/en-us/Content/Topics/Apps/Apps_App_Integration_Wizard_OIDC.htm) — the Require DPoP setting; new apps consume 50% of every API rate limit (checked 2026-09-11)
- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449.txt) — §4.2 `htu` excludes query and fragment; `ath`, `jti`, nonce (checked 2026-09-11)
- [Okta — System Log API](https://developer.okta.com/docs/api/openapi/okta-management/management/tags/systemlog) — renders client-side; read from its source, below
- [Okta — Management OpenAPI spec, `dist/2026.08.4/management-minimal.yaml`](https://github.com/okta/okta-management-openapi-spec/blob/master/dist/2026.08.4/management-minimal.yaml) — `listLogEvents`: `limit` 0–1000 default 100, `sortOrder` default `ASCENDING`, `sortOrder` wording (checked 2026-09-11)
- [OCSF schema browser](https://schema.ocsf.io/) — v1.9.0, IAM category 3, class UIDs
- [OCSF 1.3.0 schema API](https://schema.ocsf.io/api/1.3.0/classes) — the emitted version: six IAM classes, per-class required attributes and constraints, `activity_id`/`status_id`/`severity_id` enums, `cloud` and `osint` as profile attributes, Base Event as `class_uid` 0 (checked 2026-09-12)
- [OCSF schema repository, tag v1.3.0](https://github.com/ocsf/ocsf-schema/tree/v1.3.0) — `events/iam/*.json`, `events/base_event.json`, `dictionary.json` (`type_uid` formula) (checked 2026-09-12)
- [OCSF — Authentication (3002)](https://schema.ocsf.io/1.9.0/classes/authentication) — activity IDs, required attributes, `type_uid` formula
- [AWS — Collecting data from custom sources in Security Lake](https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html) — OCSF 1.3 ceiling, Parquet/zstd, partitioning, one class per object

Re-verify §2 and §4 before v1 ships. Both vendors change these pages.

---

## 9. Explicitly out of scope for v1

Splunk HEC and Datadog Logs sinks. Tailscale as a second source. A generalized
plugin registry or entry-point loader. Multi-tenant orchestration. A UI.

A narrow tool that works reads better than a half-finished framework.
