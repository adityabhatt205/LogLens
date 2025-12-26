# ── LogLens — production image ───────────────────────────────────────────
# Multi-stage: builder compiles a real wheel, runtime stage is lean.
#
# Build:  docker build -t loglens .
# Run:    docker run -p 8080:8080 -v loglens-data:/data loglens

# ── stage 1: build & install ──────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

COPY pyproject.toml .
COPY loglens/ loglens/
COPY cli/ cli/

# Regular (non-editable) install so cli/ and loglens/ are physically
# copied into site-packages — no dependency on the source directory at runtime.
RUN pip install --no-cache-dir --prefix=/install ".[web]"


# ── stage 2: runtime ──────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="LogLens"
LABEL org.opencontainers.image.description="Local log analysis with LLM support"
LABEL org.opencontainers.image.source="https://github.com/adityabhatt/loglens"

WORKDIR /app

# Packages are in site-packages — source directory is no longer needed.
COPY --from=builder /install /usr/local

# Minimal default config: point the database at the persistent /data volume.
# Override by mounting your own file: -v ./config.yaml:/app/config.yaml:ro
RUN echo "db_path: /data/loglens.db" > /app/config.yaml

# Persistent data directory (SQLite db, optional config override)
RUN mkdir -p /data

# Non-root user for safety
RUN useradd -r -u 1001 -s /bin/false loglens \
 && chown -R loglens:loglens /app /data
USER loglens

EXPOSE 8080

# Used by --reload / uvicorn factory mode
ENV LOGLENS_CONFIG=/app/config.yaml

CMD ["loglens", "serve", "--host", "0.0.0.0", "--port", "8080", "--config", "/app/config.yaml"]
