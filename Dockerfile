FROM python:3.11-slim

WORKDIR /app

# Installation des dépendances système pour psycopg2
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copie et installation des dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code
COPY . .

# Création du dossier pour la DB SQLite (si utilisée)
RUN mkdir -p /data

# Initialisation de la DB
RUN python -c "from collector import init_db; init_db()"

# Variables d'environnement par défaut
ENV PYTHONUNBUFFERED=1 \
    PORT=8080 \
    AGENTGUARD_DB_TYPE=sqlite \
    AGENTGUARD_DB_PATH=/data/agentguard.db

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/api/metrics || exit 1

# Port exposé
EXPOSE ${PORT}

# Run avec Gunicorn optimisé
CMD gunicorn --bind 0.0.0.0:${PORT} \
    --workers 4 \
    --threads 8 \
    --timeout 120 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --worker-class gthread \
    wsgi:app
