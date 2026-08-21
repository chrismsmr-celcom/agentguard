"""AgentGuard Collector — modular package."""

# ✅ Backward compatibility exports
from collector.db import init_db, get_db, is_postgres, redact_pii
from collector.app import create_app

__all__ = [
    "init_db",
    "get_db",
    "is_postgres",
    "redact_pii",
    "create_app",
]
