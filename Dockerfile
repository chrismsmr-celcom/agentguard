# =============================================================================
# AgentGuard - Production Dockerfile (Multi-stage, Non-root, Render-ready)
# =============================================================================
# Build : docker build -t agentguard:latest .
# Build avec ML : docker build --build-arg INSTALL_ML=true -t agentguard:ml .
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder — Installation des dépendances Python
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

# Dépendances système pour compilation (wheel Rust/C)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Création du venv isolé
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip setuptools wheel

COPY requirements.txt .
COPY requirements-ml.tx[t] . 2>/dev/null || true

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir -r requirements.txt

ARG INSTALL_ML=false
RUN --mount=type=cache,target=/root/.cache/pip \
    if [ "$INSTALL_ML" = "true" ] && [ -f requirements-ml.txt ]; then \
        pip install --no-cache-dir -r requirements-ml.txt; \
    fi

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-cache-dir huggingface_hub

# -----------------------------------------------------------------------------
# Stage 2: Runtime — Image minimale et sécurisée
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

LABEL maintainer="Christopher Dikesa <chris@agentguard.dev>"
LABEL org.opencontainers.image.title="AgentGuard"
LABEL org.opencontainers.image.description="Runtime Security for AI Agents"
LABEL org.opencontainers.image.version="5.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    tini \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r agentguard -g 1001 \
    && useradd -r -u 1001 -g agentguard -d /app -s /sbin/nologin agentguard \
    && mkdir -p /data /app/models /tmp/agentguard \
    && chown -R agentguard:agentguard /data /app/models /tmp/agentguard

WORKDIR /app

COPY --from=builder --chown=agentguard:agentguard /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY --chown=agentguard:agentguard . .

ARG PRELOAD_MODEL=false
ARG MODEL_NAME=protectai/deberta-v3-base-prompt-injection-v2
RUN if [ "$PRELOAD_MODEL" = "true" ]; then \
        echo "📥 Preloading ML model: ${MODEL_NAME}" && \
        python -c "from huggingface_hub import snapshot_download; \
                   snapshot_download('${MODEL_NAME}', local_dir='/app/models/prompt-injection')" && \
        chown -R agentguard:agentguard /app/models; \
    fi

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PORT=8080 \
    AGENTGUARD_DB_TYPE=sqlite \
    AGENTGUARD_DB_PATH=/data/agentguard.db \
    AGENTGUARD_LOG_LEVEL=INFO \
    WEB_CONCURRENCY=2 \
    GUNICORN_THREADS=4

# ✅ CORRECTION CRITIQUE : healthcheck dynamique via shell pour lire $PORT
# (Render injecte PORT=10000 par défaut, Gunicorn écoutera sur ce port)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT:-8080}/healthz" || exit 1

EXPOSE 8080

USER agentguard

ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["sh", "-c", "exec gunicorn \
    --bind 0.0.0.0:${PORT:-8080} \
    --workers ${WEB_CONCURRENCY:-2} \
    --threads ${GUNICORN_THREADS:-4} \
    --timeout 120 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --worker-class gthread \
    --access-logfile - \
    --error-logfile - \
    --capture-output \
    wsgi:app"]
