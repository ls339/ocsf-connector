# syntax=docker/dockerfile:1

# Two stages: the first resolves and installs dependencies, the second carries
# only the result. The build tools, the lockfile and uv itself never reach the
# image that runs in production.

FROM python:3.13-slim-bookworm AS build

# Pinned, like every other dependency here. An unpinned tool is a build that
# changes under you without a commit saying so.
COPY --from=ghcr.io/astral-sh/uv:0.13.1 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependencies first, from the lockfile, so this layer is cached until uv.lock
# changes -- editing source does not re-resolve or re-download pyarrow.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

COPY src/ ./src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable


FROM python:3.13-slim-bookworm

# Nothing above or below pins an architecture: the base image and uv are both
# multi-arch, and UV_PYTHON_DOWNLOADS=never keeps the interpreter the one the
# base image shipped for whichever platform is being built. So the same file
# builds linux/amd64 and linux/arm64 -- see docs/DEPLOYMENT.md.
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="ocsf-connector" \
      org.opencontainers.image.description="Okta System Log to OCSF 1.3 to Amazon Security Lake" \
      org.opencontainers.image.source="https://github.com/ls339/ocsf-connector" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${VCS_REF}"

# Non-root, with no login shell and no home to write to. The connector needs to
# write exactly two paths, both supplied by the platform: the state volume and
# the health file.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin --uid 10001 ocsf

COPY --from=build --chown=root:root /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001

# No CMD. The mode is a deliberate choice -- `tail` runs forever and `backfill`
# takes bounds -- and defaulting to one of them invites running the wrong one.
ENTRYPOINT ["ocsf-connector"]
