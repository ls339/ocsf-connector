# Running the connector

The connector is one long-lived process. `tail` follows the stream forever and is
a **service**; `backfill` walks a closed range and exits, so it is a **job**.
Standing up the AWS side it writes into is [`RUNBOOK.md`](RUNBOOK.md); this is
about running the thing itself.

## Building

```sh
docker build -t ocsf-connector:dev .
```

Native build, which on Apple Silicon means `linux/arm64`. Fargate runs that
directly — set `runtimePlatform.cpuArchitecture = ARM64` in the task definition
so the two match, since a mismatch fails at task start with an error that does
not obviously say "wrong architecture".

For an image anyone else will pull, build both:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg VCS_REF="$(git rev-parse --short HEAD)" \
  -t <registry>/ocsf-connector:<tag> --push .
```

Half of that is emulated on any one machine, so it belongs in CI rather than on a
laptop. A single-architecture public image quietly rules you out of environments
that do not share your laptop's architecture.

Only `linux/amd64` and `linux/arm64` are worth considering. Fargate accepts no
others, and `pyarrow` and `cryptography` publish pre-built wheels only for those
two — on anything else the build falls back to compiling Arrow C++ from source.

### What the image contains, and does not

Two stages: dependencies resolve and install in the first, and only the resulting
virtualenv is copied into the second. `uv`, the lockfile and the build tooling
never reach the image that runs.

Dependencies install from `uv.lock` with `--frozen`, so the build **fails** rather
than silently re-resolving if the lockfile is out of step with `pyproject.toml`.
An image that quietly runs different dependency versions than the tests ran
against is a bad way to spend an afternoon.

It runs as uid 10001, with no home directory and no login shell. The connector
writes exactly two paths and the platform supplies both: the state volume and the
health file.

There is no `CMD`. The entrypoint is `ocsf-connector` and the mode is the
caller's choice, because `tail` never returns and `backfill` takes bounds —
defaulting to either invites running the wrong one by omission.

The build context is an **allowlist** (`.dockerignore` starts with `*`). The
files otherwise sitting in it are `config.toml` and `*.pem`, which are live
credentials, and 1.5 GB of downloaded terraform providers.

## Configuration: the image carries none

The image contains code and nothing else, so every setting arrives from outside
it. There is no `config.toml` in it and there must not be: that file names an org
URL, a client id and a key id, and baking a tenant's identifiers into something
pushed to a registry makes the image un-shareable. With no `--config` and no
`config.toml` in the working directory the connector configures entirely from
the environment — see SPEC §6.1 for the precedence rules and `config.example.toml`
for the full variable list.

Two consequences worth knowing before you write a task definition:

- **`OCSF_SINK_PROVIDER_ROLES` packs a table into one variable**, as
  `source_name=role_arn` pairs separated by commas. It is the only setting that
  is not a scalar. All seven sources or none.
- **The connector never calls Secrets Manager.** The platform reads the secrets
  and hands them over as environment entries, so the task role needs no
  `secretsmanager:*` at all — its AWS access is `sts:AssumeRole` on the seven
  provider roles plus the EFS mount, and nothing else. The *execution* role is
  what reads the secrets, which is a different principal with a different blast
  radius.

## ECS Fargate

`deploy/ecs/task-definition.json` is the working definition with placeholders in
it. Fill them, register, and run one task.

```sh
aws ecs register-task-definition --cli-input-json file://task-definition.json
```

### One replica, and why it is not negotiable

Create the service with `--desired-count 1`, no autoscaling, and
`maximumPercent=100, minimumHealthyPercent=0`.

Those last two are the part that looks like a typo. The defaults let ECS start a
replacement task *before* draining the old one, so a routine deployment runs two
tasks at once — and two tasks keep separate cursors and separate dedup sets,
derive different batch keys from the same events, and write duplicate objects
into the lake with no error at all. The idempotent-overwrite property (§4.1)
only holds for a replay of the *same* batch key. `minimumHealthyPercent=0` buys
a few seconds of downtime, which a tail does not care about, and in exchange the
old task is always gone before the new one starts.

### The health file needs a volume whose ownership you chose

`OCSF_HEALTH_FILE` points *inside the state volume*, not at an ephemeral
`host: {}` one. That is the first thing this deployment got wrong. ECS mounts a
`host` volume root-owned, the container runs as uid 10001, and `touch` fails —
and the heartbeat deliberately does not raise, because killing a connector that
is delivering correctly to report a fault in its own monitoring is the worse
trade. So the task reported `UNHEALTHY` while its own log read
`alive: 31 pages, 413 events written`.

The connector now prints one line naming the path and the errno the first time
the write fails, which is the difference between a five-minute fix and an
afternoon. But the real fix is to put the file where ownership is declared: the
EFS access point creates its root owned by 10001, so anything under the state
mount is writable. With `readonlyRootFilesystem: true` that mount is the only
writable path in the task, which is the point.

A `tmpfs` volume would be the tidier home for a file nobody needs to survive a
restart — Fargate does not offer one.

### State on EFS

The state database must outlive the task. Mount an access point rooted at a
directory owned by uid 10001, with `transitEncryption: ENABLED` and
`authorizationConfig.iam: ENABLED`. IAM authorization means **both** policies
have to say yes: the file system policy names the task role, and the task role's
own policy names the file system — granting one and not the other fails at mount
with an error that reads like a network problem.

### The first start needs `--from-scratch`

A fresh volume holds no cursor, and tail refuses to start rather than silently
re-ingesting from `okta.since` (§6). That refusal is correct and it means the
very first run needs the flag — which a service cannot pass, since services do
not take command overrides. Bootstrap it once:

```sh
aws ecs run-task --cluster <cluster> --launch-type FARGATE \
  --task-definition ocsf-connector:1 \
  --network-configuration file://network.json \
  --overrides '{"containerOverrides":[{"name":"ocsf-connector","command":["tail","--from-scratch"]}]}'
```

**Bootstrap once.** Every `--from-scratch` run re-delivers everything from `since`
onward, and the cold-start guard cannot tell a second bootstrap from the first.
If two bootstraps send even slightly different opening queries — a different
`since`, page size or org URL — the second writes its opening batch *beside*
the first rather than over it. That leaves duplicates in the lake. It happened
on the first deployment and was found only by reconciliation (SPEC §5.5). If a
bootstrap has to be repeated, check that the state store really is empty, and
use exactly the same settings as the first attempt.

`OCSF_OKTA_SINCE` must be within the last 90 days when this runs. Okta keeps
nothing older, so an expired bound is refused with exit 2 rather than allowed
to open silently at the edge (SPEC §2.6). It is never read again after the
first commit, so it is free to age afterwards.

Let it commit at least one page, stop it, then create the service with the
unmodified `["tail"]` command. From then on every restart resumes from the
committed cursor, which is the whole point.

### Networking

Private subnets, egress through a NAT gateway, and a security group with **no
inbound rules** — the connector listens on nothing. Add an S3 *gateway* endpoint
to the private route table: Parquet delivery is the only high-volume traffic the
task produces, and a gateway endpoint carries no hourly charge and no per-GB
charge, so routing it off the NAT costs nothing and saves the NAT's data
processing fee.

Interface endpoints for ECR, CloudWatch Logs, STS and Secrets Manager are the
textbook next step and are usually the wrong call at this size: at roughly
$7/month each they cost more in total than the NAT gateway they would replace.

**If the environment has no NAT gateway already, check what one costs you before
adding it.** A dedicated NAT is about $36/month once its public IPv4 address is
counted, which for a single 0.25-vCPU task is several times the compute it
serves. The cheaper shape is a public subnet with `assignPublicIp: ENABLED` and
a security group with no inbound rules: the task is addressable at the network
layer and reachable by nothing, and its own public IPv4 costs $3.65/month
instead. What you give up is real but narrow — a misconfigured security group
becomes reachable from the internet rather than from inside the VPC, so the
blast radius of that one mistake is larger.

Private subnets behind a NAT remain the right default for production, and in an
environment that already runs one it is free to you. This repository's own demo
runs the public-subnet variant deliberately, because the NAT was most of the
bill.
