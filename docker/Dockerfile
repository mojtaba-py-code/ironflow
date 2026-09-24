# syntax=docker/dockerfile:1.7
#
# Multi-stage build.
#
# The builder compiles wheels; the runtime image carries only the interpreter,
# the installed package and its dependencies. That keeps the image small and,
# more importantly, keeps compilers and build headers out of production - they
# are the tools an attacker wants after a container escape.
#
# The runtime runs as an unprivileged user with a read-only-friendly layout:
# everything IronFlow writes lives under /var/lib/ironflow, which is the only
# path that needs to be writable.

# --------------------------------------------------------------------------- #
# Builder
# --------------------------------------------------------------------------- #
# The base is pinned by digest in both stages: a tag is a moving pointer, and
# Dependabot proposes every refresh as a reviewable change instead.
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Install into a self-contained prefix that the runtime stage copies wholesale.
RUN python -m pip install --upgrade pip \
 && python -m pip install --prefix=/install ".[columnar,excel,remote,api,postgres]"

# --------------------------------------------------------------------------- #
# Runtime
# --------------------------------------------------------------------------- #
FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS runtime

LABEL org.opencontainers.image.title="IronFlow" \
      org.opencontainers.image.description="Enterprise ETL Data Pipeline" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/mojtaba-py-code/ironflow"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    IRONFLOW_HOME=/var/lib/ironflow \
    IRONFLOW_PIPELINES_DIR=/etc/ironflow/pipelines \
    IRONFLOW_DATA_ROOTS=/data \
    IRONFLOW_LOG_JSON=true

# libpq5 for psycopg, and nothing else: no compilers, and no curl - the
# healthcheck uses the interpreter that is already here. `upgrade` applies the
# Debian security fixes published since the pinned base image was built.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends libpq5 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1001 ironflow \
 && useradd --system --uid 1001 --gid ironflow --create-home --home-dir /home/ironflow ironflow

COPY --from=builder /install /usr/local

RUN mkdir -p /var/lib/ironflow /etc/ironflow/pipelines /data \
 && chown -R ironflow:ironflow /var/lib/ironflow /data

USER ironflow
WORKDIR /home/ironflow

VOLUME ["/var/lib/ironflow", "/data"]
EXPOSE 8080

# Fails the container when the state database is unreachable or production
# hardening is violated, so an orchestrator restarts rather than silently
# serving a broken instance.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4).status != 200)"]

ENTRYPOINT ["ironflow"]
CMD ["--help"]
