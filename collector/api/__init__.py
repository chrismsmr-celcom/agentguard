"""API Blueprint registry. Splits the monolithic api.py into logical modules."""
from flask import Blueprint

# Create the main blueprint
api_bp = Blueprint("api", __name__)

# Import and register sub-modules (routes are attached to api_bp)
from collector.api import spans
from collector.api import queries
from collector.api import agents
from collector.api import approvals
from collector.api import decisions

# Note: The sub-modules must import `api_bp` from this file to register their routes.
