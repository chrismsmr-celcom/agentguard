# =============================================================================
# AgentGuard - Production Dockerfile (Multi-stage, Non-root, Air-gapped ready)
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder - Installation des dépendances
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

# Dépendances système pour compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copie requirements et installation dans venv
COPY requirements.txt .
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Installation optionnelle des dépendances ML
ARG INSTALL_ML=false
COPY requirements-ml.txt .
RUN if [ "$INSTALL_ML" = "true" ]; then \
        pip install --no-cache-dir -r requirements-ml.txt; \
    fi

# -----------------------------------------------------------------------------
# Stage 2: Runtime - Image minimale et sécurisée
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

# Labels OCI
LABEL maintainer="Christopher Dikesa"
LABEL org.opencontainers.image.title="AgentGuard"
LABEL org.opencontainers.image.description="Runtime Security for AI Agents"

# Dépendances runtime uniquement
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r agentguard -g 1001 \
    && useradd -r -u 1001 -g agentguard -d /app -s /sbin/nologin agentguard

WORKDIR /app

# Copie du venv depuis le builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copie du code source
COPY . .

# Création des dossiers de données
RUN mkdir -p /data /app/models /tmp/agentguard \
    && chown -R agentguard:agentguard /data /app/models /tmp/agentguard

# Pré-téléchargement du modèle ML (optionnel, activé par argument)
ARG PRELOAD_MODEL=false
ARG MODEL_NAME=protectai/deberta-v3-base-prompt-injection-v2
RUN if [ "$PRELOAD_MODEL" = "true" ]; then \
        python -c "from huggingface_hub import snapshot_download; \
                   snapshot_download('${MODEL_NAME}', local_dir='/app/models/prompt-injection')" || true; \
    fi

# Variables d'environnement par défaut
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PORT=8080 \
    AGENTGUARD_DB_TYPE=sqlite \
    AGENTGUARD_DB_PATH=/data/agentguard.db \
    AGENTGUARD_LOG_LEVEL=INFO

# Healthcheck optimisé
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${PORT}/healthz || exit 1

# Exposition du port
EXPOSE ${PORT}

# Utilisateur non-root
USER agentguard

# Point d'entrée avec tini (gestion propre des signaux)
ENTRYPOINT ["/usr/bin/tini", "--"]

# Commande Gunicorn optimisée pour production
CMD ["gunicorn", \
     "--bind", "0.0.0.0:${PORT}", \
     "--workers", "${WEB_CONCURRENCY:-2}", \
     "--threads", "${GUNICORN_THREADS:-4}", \
     "--timeout", "120", \
     "--keep-alive", "5", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--worker-class", "gthread", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--capture-output", \
     "wsgi:app"]
