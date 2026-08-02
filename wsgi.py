"""
WSGI entry point for Gunicorn
"""
from collector import app, init_db

# Initialise la DB au démarrage
init_db()

if __name__ == "__main__":
    app.run()
