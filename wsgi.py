"""
WSGI entry point for Gunicorn (v3.0 prod-ready).
"""
import logging
from collector import app, init_db

logging.basicConfig(
    level=logging.getLogger().level,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

# Initialise la DB au démarrage (idempotent + verrou advisory côté PG)
init_db()

if __name__ == "__main__":
    app.run()
