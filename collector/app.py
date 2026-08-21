"""Flask app factory + global config."""
import os
import secrets
import structlog
from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import URLSafeTimedSerializer

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger("agentguard.collector")


def create_app() -> Flask:
    """Crée et configure l'application Flask."""
    app = Flask(__name__)
    
    # ✅ Security hardening : environnement
    app.config["ENVIRONMENT"] = os.environ.get("AGENTGUARD_ENVIRONMENT", "development")
    is_production = app.config["ENVIRONMENT"] == "production"
    
    # ✅ FLASK SECRET : fail-closed en production
    flask_secret = os.environ.get("AGENTGUARD_FLASK_SECRET")
    if not flask_secret:
        if is_production:
            raise RuntimeError(
                "AGENTGUARD_FLASK_SECRET must be configured in production. "
                "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )
        else:
            flask_secret = secrets.token_urlsafe(32)
            logger.warning("flask_secret_auto_generated_dev_only")
    app.secret_key = flask_secret
    
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("AGENTGUARD_MAX_BODY_BYTES", "262144"))
    
    
    # CORS : strict en production, permissif en dev
    cors_origins = [x.strip() for x in os.environ.get("AGENTGUARD_CORS_ORIGINS", "").split(",") if x.strip()]
    
    if app.config["ENVIRONMENT"] == "production":
        if not cors_origins:
            raise RuntimeError(
                "AGENTGUARD_CORS_ORIGINS must be configured in production. "
                "Example: AGENTGUARD_CORS_ORIGINS=https://dashboard.example.com"
            )
        CORS(app, origins=cors_origins, supports_credentials=True)
        logger.info("cors_strict_mode", origins=cors_origins)
    else:
        CORS(app, origins=cors_origins or "*", supports_credentials=True)
    
    # Rate limiter
    app.limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[os.environ.get("AGENTGUARD_RATE_LIMIT", "120 per minute")],
        storage_uri=os.environ.get("AGENTGUARD_LIMITER_STORAGE", "memory://"),
    )
    
    # Auth serializer
    app.auth_serializer = URLSafeTimedSerializer(app.secret_key, salt="agentguard-auth-v1")
    app.auth_session_ttl = int(os.environ.get("AGENTGUARD_AUTH_SESSION_TTL", "900"))
    app.auth_cookie_secure = os.environ.get("AGENTGUARD_COOKIE_SECURE", "true").lower() == "true"
    
    # Config globale
    app.config["DB_TYPE"] = os.environ.get("AGENTGUARD_DB_TYPE", "sqlite")
    app.config["DATABASE_URL"] = os.environ.get("DATABASE_URL", "")
    app.config["API_KEY"] = os.environ.get("AGENTGUARD_API_KEY", None)
    app.config["ADMIN_SECRET"] = os.environ.get("AGENTGUARD_ADMIN_SECRET")
    app.config["AUTH_COOKIE"] = "ag_auth"
    app.config["SPAN_RATE_LIMIT"] = os.environ.get("AGENTGUARD_SPAN_RATE_LIMIT", "30 per minute")
    
    # ✅ FAIL CLOSED en production si secrets manquants
    if app.config["ENVIRONMENT"] == "production":
        if not app.config["API_KEY"]:
            raise RuntimeError(
                "AGENTGUARD_API_KEY must be configured in production. "
                "Set it via environment variable. Refusing to start without it."
            )
        if not app.config["ADMIN_SECRET"]:
            logger.warning(
                "admin_secret_missing_in_production",
                note="Admin endpoints will be disabled",
            )
    
    # Génération auto de la clé API si absente (dev only)
    if not app.config["API_KEY"]:
        if app.config["ENVIRONMENT"] == "development":
            app.config["API_KEY"] = "ag-" + secrets.token_urlsafe(32)
            app.config["_API_KEY_WAS_GENERATED"] = True
            logger.warning("api_key_generated_in_memory_dev_only")
        else:
            raise RuntimeError(
                "AGENTGUARD_API_KEY required in non-development environments"
            )
    else:
        app.config["_API_KEY_WAS_GENERATED"] = False
    
    # Warning si clé auto-générée en PostgreSQL (production-like)
    if app.config["_API_KEY_WAS_GENERATED"] and app.config["DB_TYPE"] == "postgres":
        logger.warning(
            "api_key_generated_but_postgres_active",
            note="Configure AGENTGUARD_API_KEY in env to persist across restarts",
        )
    
    # Enregistre les blueprints
    _register_blueprints(app)
    
    # Error handler global
    @app.errorhandler(Exception)
    def handle_unexpected_error(e):
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return e
        app.logger.exception("Unhandled error")
        from flask import jsonify
        return jsonify({"error": "Internal server error"}), 500
    
    logger.info(
        "app_created",
        environment=app.config["ENVIRONMENT"],
        db_type=app.config["DB_TYPE"],
        legacy_key_allowed=app.config["ALLOW_LEGACY_SYSTEM_KEY"],
    )
    
    return app


def _register_blueprints(app: Flask):
    """Enregistre tous les blueprints."""
    from collector.auth import auth_bp
    from collector.api import api_bp
    from collector.admin import admin_bp
    from collector.audit_routes import audit_bp
    from collector.trace_view import trace_bp
    from collector.identity_routes import identity_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(trace_bp)
    app.register_blueprint(identity_bp)


def init_db():
    """Initialise la DB (à appeler au boot)."""
    from collector.db import init_db as _init_db
    _init_db()
