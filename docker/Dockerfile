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
FROM python:3.14-slim-bookworm AS builder

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
FROM python:3.14-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="IronFlow" \
      org.opencontainers.image.description="Enterprise ETL data pipeline platform" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/mojtaba-py-code/ironflow"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    IRONFLOW_HOME=/var/lib/ironflow \
    IRONFLOW_PIPELINES_DIR=/etc/ironflow/pipelines \
    IRONFLOW_DATA_ROOTS=/data \
    IRONFLOW_LOG_JSON=true

# libpq5 for psycopg; curl for the healthcheck. No compilers.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpq5 curl \
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
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["ironflow"]
CMD ["--help"]
