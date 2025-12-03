# syntax=docker/dockerfile:1.5
####################################
# Builder: create wheel from source
####################################
FROM python:3.12-slim AS builder

# Build args allow CI to inject the version (e.g. v1.0.11)
ARG VERSION
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_SLOWQL=$VERSION

WORKDIR /src

# Install build-time system deps. Keep small and explicit.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
 && rm -rf /var/lib/apt/lists/*

# Install pip tooling used to build wheel
RUN python -m pip install --upgrade pip build setuptools wheel

# Copy project metadata and source code
COPY pyproject.toml README.md LICENSE /src/
COPY src/ /src/src/

# Build wheel into /out with explicit SCM version injection
RUN python -m build --wheel --outdir /out


####################################
# Runtime image: minimal, only runtime deps
####################################
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8

WORKDIR /app

# Runtime system deps (keep ca-certificates for HTTPS)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy built wheel from builder stage and install it
COPY --from=builder /out /out
RUN pip install /out/slowql-*.whl \
 && rm -rf /root/.cache/pip /out

# Use a non-root user for better security
RUN groupadd --gid 1000 slowql && useradd --uid 1000 --gid slowql --create-home slowql
USER slowql
WORKDIR /home/slowql

# Default CLI entrypoint
ENTRYPOINT ["slowql"]
CMD ["--help"]
