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
