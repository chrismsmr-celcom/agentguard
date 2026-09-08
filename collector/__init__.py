"""AgentGuard Collector — modular package."""

# ✅ Backward compatibility exports
from collector.db import init_db, get_db, is_postgres, redact_pii, sql_true, sql_false, sql_placeholder
from collector.app import create_app

__all__ = [
    "init_db",
    "get_db",
    "is_postgres",
    "redact_pii",
    "sql_true",
    "sql_false",
    "sql_placeholder",
    "create_app",
]
