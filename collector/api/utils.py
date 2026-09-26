import json
import structlog
from collector.db import get_db, is_postgres

logger = structlog.get_logger("agentguard.api.utils")

def _as_json(value, default):
    """PostgreSQL (JSONB) renvoie déjà dict/list ; SQLite renvoie du texte."""
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default

def _iso_utc(value):
    """Horodatage -> ISO 8601 UTC ('...Z')."""
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        text = value.isoformat()
    else:
        text = str(value).replace(" ", "T")
    if text.endswith("Z") or "+" in text[10:]:
        return text
    return text.split(".")[0] + "Z"

def _db_run(sql, params=(), fetch=None, commit=False):
    """Exécute une requête écrite avec des '?' (converti en %s pour PostgreSQL)."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(sql.replace("?", "%s") if is_postgres() else sql, params)
        out = None
        if fetch == "one":
            out = cur.fetchone()
        elif fetch == "all":
            out = cur.fetchall()
        rowcount = cur.rowcount
        if commit:
            conn.commit()
        return out, rowcount
    finally:
        conn.close()
