"""
WSGI entry point for Gunicorn.
"""
from collector.app import create_app, init_db

# Initialise la DB au boot
init_db()

# Crée l'instance Flask
app = create_app()
