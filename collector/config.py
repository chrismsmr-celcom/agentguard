import os
from pydantic_settings import BaseSettings
from pydantic import Field, ValidationError
import logging

logger = logging.getLogger("cerbere.config")

class AppConfig(BaseSettings):
    """Configuration centrale validée au démarrage."""
    
    # ENVIRONNEMENT
    environment: str = Field(default="development", env="ENVIRONMENT")
    
    # AUTH & SECRETS
    agentguard_api_key: str = Field(default="", env="AGENTGUARD_API_KEY")
    agentguard_admin_secret: str = Field(default="", env="AGENTGUARD_ADMIN_SECRET")
    agentguard_flask_secret: str = Field(default="dev-secret-change-me", env="AGENTGUARD_FLASK_SECRET")
    
    # SESSIONS & SECURITY
    magic_link_ttl_seconds: int = Field(default=300, env="AGENTGUARD_MAGIC_LINK_TTL") # Réduit à 5 min (Audit)
    auth_session_ttl_seconds: int = Field(default=28800, env="AGENTGUARD_AUTH_SESSION_TTL")
    
    # DATABASE
    agentguard_db_type: str = Field(default="sqlite", env="AGENTGUARD_DB_TYPE")
    database_url: str = Field(default="sqlite:///./agentguard.db", env="DATABASE_URL")
    
    # CORS & RESEAU
    agentguard_cors_origins: str = Field(default="*", env="AGENTGUARD_CORS_ORIGINS")
    port: int = Field(default=8080, env="PORT")

    def validate_production(self) -> list[str]:
        """Bloque le démarrage si la config est invalide en production."""
        if self.environment == "production":
            errors = []
            if not self.agentguard_api_key:
                errors.append("AGENTGUARD_API_KEY est requis en production")
            if not self.agentguard_admin_secret:
                errors.append("AGENTGUARD_ADMIN_SECRET est requis en production")
            if self.agentguard_flask_secret == "dev-secret-change-me":
                errors.append("AGENTGUARD_FLASK_SECRET doit être changé en production")
            if self.agentguard_cors_origins == "*":
                errors.append("AGENTGUARD_CORS_ORIGINS ne peut pas être '*' en production")
            if self.agentguard_db_type == "sqlite":
                errors.append("SQLite n'est pas autorisé en production (utilisez PostgreSQL)")
            return errors
        return []

# Instance globale
try:
    config = AppConfig()
    prod_errors = config.validate_production()
    if prod_errors:
        logger.critical("❌ CONFIGURATION PRODUCTION INVALIDE :")
        for err in prod_errors:
            logger.critical(f"  - {err}")
        raise RuntimeError("Configuration de production invalide. Voir les logs ci-dessus.")
    logger.info(f"✅ Configuration chargée avec succès (Env: {config.environment})")
except ValidationError as e:
    logger.critical(f"❌ Erreur de validation de configuration : {e}")
    raise
