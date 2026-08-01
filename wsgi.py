"""
WSGI entry point for Render / Gunicorn.
Initialise la DB au démarrage du worker.
"""
from collector import app, init_db

# Initialise la base de données au premier import
init_db()
