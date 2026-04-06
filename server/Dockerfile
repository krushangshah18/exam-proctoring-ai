# ─── Stage 1: Dependency builder ─────────────────────────────────────────────
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files — separate layer so it only rebuilds when deps change
COPY pyproject.toml uv.lock ./

# Install all production deps into .venv
RUN uv sync --frozen --no-dev --no-install-project


# ─── Stage 2: Runtime image ───────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Runtime system libs only — no build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # OpenCV headless
    libgl1 \
    libglib2.0-0 \
    # psycopg2
    libpq5 \
    # healthcheck
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy virtualenv from builder (no uv, no compilers in final image)
COPY --from=builder /app/.venv /app/.venv

# Copy application code
COPY app/           ./app/
COPY alembic/       ./alembic/
COPY alembic.ini    ./alembic.ini
# YOLO fallback model (used when engine is not connected)
COPY finalBestV5.pt ./finalBestV5.pt

# Pre-create runtime directories (volumes will overlay these at runtime)
RUN mkdir -p storage/profiles storage/evidence storage/audio storage/temp logs

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Single worker — required because SSE queues, identity check tasks,
# and the exam scheduler are all in-memory (multi-worker breaks SSE delivery).
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD curl -sf http://localhost:8000/health | grep -q "ok" || exit 1

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--loop", "uvloop", \
     "--http", "httptools", \
     "--timeout-keep-alive", "120"]
