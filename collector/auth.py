"""Authentication + session management + RBAC + passwordless magic-link login."""

import hashlib
import os
import secrets
import smtplib
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from typing import Optional

import structlog
from flask import (
    Blueprint,
    current_app,
    g,
    jsonify,
    redirect,
    render_template_string,
    request,
    url_for,
)

from collector.db import (
    _get_db_path,
    get_pg_conn,
    get_sqlite_conn,
    is_postgres,
    resolve_agent_identity,
)

logger = structlog.get_logger("agentguard.auth")

# IMPORTANT:
# collector/app.py imports this exact symbol.
auth_bp = Blueprint("auth", __name__)


# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

MAGIC_LINK_TTL_SECONDS = 10 * 60
HUMAN_SESSION_TTL_SECONDS = 8 * 60 * 60
MAGIC_LINK_TOKEN_BYTES = 32

MAGIC_LINK_COOKIE = "cerbere_session"

MAGIC_LINK_ENABLED = (
    os.environ.get("AGENTGUARD_MAGIC_LINK_ENABLED", "true").lower()
    in {"1", "true", "yes", "on"}
)

SMTP_HOST = os.environ.get("SMTP_HOST", "").strip()
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get(
    "SMTP_FROM",
    SMTP_USERNAME or "security@agentguard.local",
).strip()
SMTP_USE_TLS = (
    os.environ.get("SMTP_USE_TLS", "true").lower()
    in {"1", "true", "yes", "on"}
)

APP_BASE_URL = os.environ.get(
    "APP_BASE_URL",
    os.environ.get(
        "AGENTGUARD_APP_URL",
        "http://localhost:5000",
    ),
).rstrip("/")


# ═══════════════════════════════════════════════════════════════
# PROTECTED ENDPOINTS
# ═══════════════════════════════════════════════════════════════

PROTECTED_ENDPOINTS = {
    "api.receive_span",
    "api.list_traces",
    "api.get_trace",
    "api.get_metrics",
    "auth.dashboard",
    "trace.trace_detail",
    "api.get_detection_stats",
    "api.api_models",
    "api.api_heatmap",
    "api.api_checks_breakdown",
    "api.api_expensive_spans",
    "api.api_cost_trend",
    "api.api_latency_distribution",
    "api.api_recent_events",
    "api.api_trend_daily",
    "api.get_llm_stats",
    "api.api_audit_trail",
    "api.api_checks_daily",
    "api.api_models_daily",
    "audit.audit_stats",
    "audit.audit_verify",
    "audit.audit_query",
    "identity.create_tenant",
    "identity.create_org",
    "identity.create_user",
    "identity.create_agent",
    "identity.revoke_agent",
    "identity.list_agents",
    "identity.get_me",
}


# ═══════════════════════════════════════════════════════════════
# BASIC CRYPTO HELPERS
# ═══════════════════════════════════════════════════════════════

def safe_compare(a: str, b: str) -> bool:
    if not a or not b:
        return False

    try:
        return secrets.compare_digest(
            str(a).encode("utf-8"),
            str(b).encode("utf-8"),
        )
    except Exception:
        return False


def hash_key(key: str) -> str:
    return hashlib.sha256(
        str(key).encode("utf-8")
    ).hexdigest()


def _hash_magic_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _parse_datetime(value):
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    value = str(value)

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    except Exception:
        return None


def _normalize_email(email: str) -> str:
    return str(email or "").strip().lower()


def _valid_email(email: str) -> bool:
    email = _normalize_email(email)

    if len(email) < 5 or len(email) > 254:
        return False

    if "@" not in email:
        return False

    local, domain = email.rsplit("@", 1)

    if not local or not domain:
        return False

    if "." not in domain:
        return False

    if domain.startswith(".") or domain.endswith("."):
        return False

    return True


# ═══════════════════════════════════════════════════════════════
# DATABASE HELPERS
# ═══════════════════════════════════════════════════════════════

def _db_execute(query: str, params=(), fetchone=False, fetchall=False):
    """
    Execute a SELECT query against PostgreSQL or SQLite.

    This helper deliberately keeps connection handling local so
    authentication does not leak database connections.
    """
    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()
            cur.execute(query, params)

            if fetchone:
                return cur.fetchone()

            if fetchall:
                return cur.fetchall()

            conn.commit()
            return None
        finally:
            conn.close()

    conn = get_sqlite_conn()
    try:
        cur = conn.cursor()
        cur.execute(query, params)

        if fetchone:
            return cur.fetchone()

        if fetchall:
            return cur.fetchall()

        conn.commit()
        return None
    finally:
        conn.close()


def _user_by_email(email: str):
    email = _normalize_email(email)

    if not email:
        return None

    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT
                    user_id,
                    org_id,
                    tenant_id,
                    email,
                    display_name,
                    role,
                    active
                FROM users
                WHERE LOWER(email) = %s
                LIMIT 1
                """,
                (email,),
            )
            return cur.fetchone()
        finally:
            conn.close()

    conn = sqlite3.connect(_get_db_path())
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                user_id,
                org_id,
                tenant_id,
                email,
                display_name,
                role,
                active
            FROM users
            WHERE LOWER(email) = ?
            LIMIT 1
            """,
            (email,),
        )
        return cur.fetchone()
    finally:
        conn.close()


def _user_by_id(user_id: str):
    if not user_id:
        return None

    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT
                    user_id,
                    org_id,
                    tenant_id,
                    email,
                    display_name,
                    role,
                    active
                FROM users
                WHERE user_id = %s
                LIMIT 1
                """,
                (user_id,),
            )
            return cur.fetchone()
        finally:
            conn.close()

    conn = sqlite3.connect(_get_db_path())
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                user_id,
                org_id,
                tenant_id,
                email,
                display_name,
                role,
                active
            FROM users
            WHERE user_id = ?
            LIMIT 1
            """,
            (user_id,),
        )
        return cur.fetchone()
    finally:
        conn.close()


def _user_is_active(user_id: str) -> bool:
    row = _user_by_id(user_id)

    if not row:
        return False

    return bool(row[6])


# ═══════════════════════════════════════════════════════════════
# MAGIC LINK STORAGE
# ═══════════════════════════════════════════════════════════════

def _ensure_magic_link_table():
    """
    Defensive migration.

    collector/db.py should create this table during normal startup.
    This fallback prevents authentication from breaking if an older
    database was created before the migration.
    """

    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS magic_link_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id),
                    expires_at TIMESTAMPTZ NOT NULL,
                    used_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_magic_link_tokens_user
                ON magic_link_tokens(user_id)
                """
            )

            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_magic_link_tokens_expires
                ON magic_link_tokens(expires_at)
                """
            )

            conn.commit()
        finally:
            conn.close()

        return

    conn = sqlite3.connect(_get_db_path())
    try:
        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS magic_link_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_magic_link_tokens_user
            ON magic_link_tokens(user_id)
            """
        )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_magic_link_tokens_expires
            ON magic_link_tokens(expires_at)
            """
        )

        conn.commit()
    finally:
        conn.close()


def _invalidate_existing_magic_links(user_id: str):
    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE magic_link_tokens
                SET used_at = CURRENT_TIMESTAMP
                WHERE user_id = %s
                  AND used_at IS NULL
                """,
                (user_id,),
            )
            conn.commit()
        finally:
            conn.close()

        return

    conn = sqlite3.connect(_get_db_path())
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE magic_link_tokens
            SET used_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
              AND used_at IS NULL
            """,
            (user_id,),
        )
        conn.commit()
    finally:
        conn.close()


def _store_magic_link(
    user_id: str,
    token_hash: str,
    expires_at: datetime,
):
    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()

            cur.execute(
                """
                INSERT INTO magic_link_tokens
                    (token_hash, user_id, expires_at)
                VALUES
                    (%s, %s, %s)
                """,
                (
                    token_hash,
                    user_id,
                    expires_at,
                ),
            )

            conn.commit()
        finally:
            conn.close()

        return

    conn = sqlite3.connect(_get_db_path())
    try:
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO magic_link_tokens
                (token_hash, user_id, expires_at)
            VALUES
                (?, ?, ?)
            """,
            (
                token_hash,
                user_id,
                _utc_iso(expires_at),
            ),
        )

        conn.commit()
    finally:
        conn.close()


def _consume_magic_link(token: str):
    """
    Atomically validates and consumes a magic link.

    Returns the user row or None.
    """
    if not token:
        return None

    token_hash = _hash_magic_token(token)
    now = _utcnow()

    if is_postgres():
        conn = get_pg_conn()

        try:
            cur = conn.cursor()

            cur.execute(
                """
                SELECT
                    token_hash,
                    user_id,
                    expires_at,
                    used_at
                FROM magic_link_tokens
                WHERE token_hash = %s
                FOR UPDATE
                """,
                (token_hash,),
            )

            row = cur.fetchone()

            if not row:
                conn.rollback()
                return None

            stored_hash = row[0]
            user_id = row[1]
            expires_at = _parse_datetime(row[2])
            used_at = row[3]

            if not safe_compare(stored_hash, token_hash):
                conn.rollback()
                return None

            if used_at is not None:
                conn.rollback()
                return None

            if expires_at is None or expires_at <= now:
                conn.rollback()
                return None

            cur.execute(
                """
                UPDATE magic_link_tokens
                SET used_at = CURRENT_TIMESTAMP
                WHERE token_hash = %s
                  AND used_at IS NULL
                """,
                (token_hash,),
            )

            if cur.rowcount != 1:
                conn.rollback()
                return None

            cur.execute(
                """
                SELECT
                    user_id,
                    org_id,
                    tenant_id,
                    email,
                    display_name,
                    role,
                    active
                FROM users
                WHERE user_id = %s
                LIMIT 1
                """,
                (user_id,),
            )

            user = cur.fetchone()

            if not user or not bool(user[6]):
                conn.rollback()
                return None

            conn.commit()
            return user

        finally:
            conn.close()

    conn = sqlite3.connect(
        _get_db_path(),
        timeout=10,
    )

    try:
        conn.execute("BEGIN IMMEDIATE")

        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                token_hash,
                user_id,
                expires_at,
                used_at
            FROM magic_link_tokens
            WHERE token_hash = ?
            """,
            (token_hash,),
        )

        row = cur.fetchone()

        if not row:
            conn.rollback()
            return None

        stored_hash = row[0]
        user_id = row[1]
        expires_at = _parse_datetime(row[2])
        used_at = row[3]

        if not safe_compare(stored_hash, token_hash):
            conn.rollback()
            return None

        if used_at is not None:
            conn.rollback()
            return None

        if expires_at is None or expires_at <= now:
            conn.rollback()
            return None

        cur.execute(
            """
            UPDATE magic_link_tokens
            SET used_at = ?
            WHERE token_hash = ?
              AND used_at IS NULL
            """,
            (
                _utc_iso(now),
                token_hash,
            ),
        )

        if cur.rowcount != 1:
            conn.rollback()
            return None

        cur.execute(
            """
            SELECT
                user_id,
                org_id,
                tenant_id,
                email,
                display_name,
                role,
                active
            FROM users
            WHERE user_id = ?
            LIMIT 1
            """,
            (user_id,),
        )

        user = cur.fetchone()

        if not user or not bool(user[6]):
            conn.rollback()
            return None

        conn.commit()
        return user

    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════
# MAGIC LINK EMAIL
# ═══════════════════════════════════════════════════════════════

def _build_magic_link(token: str) -> str:
    return (
        f"{APP_BASE_URL}/auth/verify"
        f"?token={token}"
    )


def _send_magic_link_email(email: str, link: str):
    subject = "Sign in to Cerbere"

    text = f"""Sign in to Cerbere

Use the secure link below to access your security console:

{link}

This link expires in 10 minutes and can only be used once.

If you did not request this email, you can safely ignore it.
"""

    html = f"""
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Sign in to Cerbere</title>
</head>
<body style="
    margin:0;
    padding:40px 20px;
    background:#07111f;
    color:#eef5ff;
    font-family:Arial,Helvetica,sans-serif;
">
<div style="
    max-width:520px;
    margin:0 auto;
    background:#0d1b2d;
    border:1px solid #21334a;
    border-radius:18px;
    padding:32px;
">
    <div style="
        font-size:14px;
        color:#38bdf8;
        font-weight:700;
        letter-spacing:.08em;
        text-transform:uppercase;
    ">
        Cerbere
    </div>

    <h1 style="
        margin:16px 0 10px;
        color:#ffffff;
        font-size:26px;
    ">
        Sign in to your security console
    </h1>

    <p style="
        color:#a8bad0;
        line-height:1.6;
    ">
        Use the secure link below to continue.
    </p>

    <p style="margin:28px 0;">
        <a href="{link}" style="
            display:inline-block;
            padding:14px 22px;
            border-radius:10px;
            background:#2563eb;
            color:#ffffff;
            text-decoration:none;
            font-weight:700;
        ">
            Sign in to Cerbere
        </a>
    </p>

    <p style="
        color:#71859d;
        font-size:13px;
        line-height:1.6;
    ">
        This link expires in 10 minutes and can only be used once.
    </p>

    <p style="
        color:#71859d;
        font-size:12px;
        line-height:1.6;
    ">
        If you did not request this email, you can safely ignore it.
    </p>
</div>
</body>
</html>
"""

    if not SMTP_HOST:
        environment = current_app.config.get(
            "ENVIRONMENT",
            "development",
        )

        if environment == "production":
            raise RuntimeError(
                "SMTP_HOST must be configured in production "
                "to send magic-link emails."
            )

        logger.warning(
            "magic_link_email_not_sent_smtp_not_configured",
            email=email,
            magic_link=link,
        )
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = SMTP_FROM
    message["To"] = email

    message.set_content(text)
    message.add_alternative(
        html,
        subtype="html",
    )

    with smtplib.SMTP(
        SMTP_HOST,
        SMTP_PORT,
        timeout=15,
    ) as smtp:
        if SMTP_USE_TLS:
            smtp.starttls()

        if SMTP_USERNAME:
            smtp.login(
                SMTP_USERNAME,
                SMTP_PASSWORD,
            )

        smtp.send_message(message)

    logger.info(
        "magic_link_email_sent",
        email_domain=email.split("@", 1)[-1],
    )

    return True


# ═══════════════════════════════════════════════════════════════
# HUMAN SESSION
# ═══════════════════════════════════════════════════════════════

def _human_session_token(user_id: str) -> str:
    """
    Signed server-generated session.

    The signing serializer is configured by collector/app.py.
    """
    payload = {
        "type": "human",
        "user_id": user_id,
        "nonce": secrets.token_urlsafe(16),
    }

    return current_app.auth_serializer.dumps(payload)


def _resolve_human_session(token: str):
    if not token:
        return None

    try:
        payload = current_app.auth_serializer.loads(
            token,
            max_age=HUMAN_SESSION_TTL_SECONDS,
        )
    except Exception:
        return None

    if payload.get("type") != "human":
        return None

    user_id = payload.get("user_id")

    if not user_id:
        return None

    user = _user_by_id(user_id)

    if not user:
        return None

    if not bool(user[6]):
        return None

    return user


def _set_human_session(response, user_id: str):
    cookie_name = current_app.config.get(
        "AUTH_COOKIE",
        MAGIC_LINK_COOKIE,
    )

    token = _human_session_token(user_id)

    response.set_cookie(
        cookie_name,
        token,
        httponly=True,
        secure=bool(
            getattr(
                current_app,
                "auth_cookie_secure",
                True,
            )
        ),
        samesite="Lax",
        max_age=HUMAN_SESSION_TTL_SECONDS,
        path="/",
    )

    return response


def _clear_human_session(response):
    cookie_name = current_app.config.get(
        "AUTH_COOKIE",
        MAGIC_LINK_COOKIE,
    )

    response.delete_cookie(
        cookie_name,
        path="/",
    )

    return response


# ═══════════════════════════════════════════════════════════════
# LEGACY API-KEY SESSION
# ═══════════════════════════════════════════════════════════════

def _lookup_org_by_key(key: str):
    """Legacy lookup in api_keys."""
    if not key:
        return None

    key_hash = hash_key(key)

    if is_postgres():
        conn = get_pg_conn()

        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT org_id
                FROM api_keys
                WHERE key_hash = %s
                  AND active = TRUE
                LIMIT 1
                """,
                (key_hash,),
            )
            row = cur.fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    conn = sqlite3.connect(_get_db_path())

    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT org_id
            FROM api_keys
            WHERE key_hash = ?
              AND active = 1
            LIMIT 1
            """,
            (key_hash,),
        )
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def resolve_org_id(key: str):
    """
    Resolve an API key to an organization.

    Supported:
      - agp_* platform identity
      - configured legacy system key
      - ag_* agent key
      - legacy api_keys table
    """
    if not key:
        return None

    # Platform identity
    try:
        from collector.platform_identity import (
            PLATFORM_KEY_PREFIX,
            resolve_platform_identity,
        )

        if key.startswith(PLATFORM_KEY_PREFIX):
            platform_identity = resolve_platform_identity(key)

            if platform_identity:
                g.platform_identity = platform_identity

                logger.info(
                    "platform_identity_resolved",
                    service=platform_identity.get(
                        "service_name"
                    ),
                )

                return "platform"

    except Exception as exc:
        logger.warning(
            "platform_identity_resolution_failed",
            error=str(exc),
        )

    # Legacy global key
    api_key = current_app.config.get("API_KEY")

    if api_key and safe_compare(key, api_key):
        logger.warning(
            "legacy_system_key_used",
            ip=request.remote_addr,
            endpoint=request.endpoint,
            note="Deprecated.",
        )

        return "default"

    # Agent key
    try:
        identity = resolve_agent_identity(key)
    except Exception as exc:
        logger.warning(
            "agent_identity_resolution_failed",
            error=str(exc),
        )
        identity = None

    if identity:
        g.agent_identity = identity
        return identity["org_id"]

    # Legacy api_keys table
    try:
        return _lookup_org_by_key(key)
    except Exception as exc:
        logger.warning(
            "legacy_api_key_lookup_failed",
            error=str(exc),
        )
        return None


def _session_token(org_id: str, key_hash: str) -> str:
    return current_app.auth_serializer.dumps(
        {
            "type": "api_key",
            "org_id": org_id,
            "key_hash": key_hash,
        }
    )


def _session_org_id(token: str):
    if not token:
        return None

    try:
        payload = current_app.auth_serializer.loads(
            token,
            max_age=current_app.config.get(
                "AUTH_SESSION_TTL",
                3600,
            ),
        )

        if payload.get("type") not in {
            None,
            "api_key",
        }:
            return None

        org_id = payload.get("org_id")
        key_hash = payload.get("key_hash")

        if not org_id or not key_hash:
            return None

        if org_id == "default":
            api_key = current_app.config.get("API_KEY")

            if api_key and safe_compare(
                key_hash,
                hash_key(api_key),
            ):
                return "default"

            return None

        if is_postgres():
            conn = get_pg_conn()

            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT 1
                    FROM api_keys
                    WHERE org_id = %s
                      AND key_hash = %s
                      AND active = TRUE
                    LIMIT 1
                    """,
                    (
                        org_id,
                        key_hash,
                    ),
                )

                return (
                    org_id
                    if cur.fetchone()
                    else None
                )
            finally:
                conn.close()

        conn = sqlite3.connect(_get_db_path())

        try:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT 1
                FROM api_keys
                WHERE org_id = ?
                  AND key_hash = ?
                  AND active = 1
                LIMIT 1
                """,
                (
                    org_id,
                    key_hash,
                ),
            )

            return (
                org_id
                if cur.fetchone()
                else None
            )
        finally:
            conn.close()

    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════
# IDENTITY RESOLUTION
# ═══════════════════════════════════════════════════════════════

def _build_user_identity(user):
    try:
        from identity import (
            IdentityType,
            ResolvedIdentity,
            Role,
        )
    except ImportError:
        return None

    if not user:
        return None

    (
        user_id,
        org_id,
        tenant_id,
        email,
        display_name,
        role_value,
        active,
    ) = user

    if not active:
        return None

    try:
        role = Role(str(role_value).lower())
    except Exception:
        try:
            role = Role.VIEWER
        except Exception:
            role = role_value

    identity_type = None

    for candidate in (
        "USER",
        "HUMAN",
        "SESSION",
    ):
        try:
            identity_type = getattr(
                IdentityType,
                candidate,
            )
            break
        except Exception:
            continue

    if identity_type is None:
        try:
            identity_type = IdentityType.USER
        except Exception:
            return None

    kwargs = {
        "identity_type": identity_type,
        "tenant_id": tenant_id,
        "org_id": org_id,
        "subject_id": user_id,
        "role": role,
    }

    for field, value in (
        ("user_email", email),
        ("email", email),
        ("display_name", display_name),
    ):
        try:
            kwargs[field] = value
            return ResolvedIdentity(**kwargs)
        except TypeError:
            kwargs.pop(field, None)

    try:
        return ResolvedIdentity(**kwargs)
    except Exception as exc:
        logger.warning(
            "resolved_identity_build_failed",
            error=str(exc),
        )
        return None


def resolve_full_identity():
    """
    Resolve the complete identity for the current request.
    """
    try:
        from identity import (
            IdentityType,
            ResolvedIdentity,
            Role,
        )
    except ImportError:
        return None

    if getattr(g, "identity", None) is not None:
        return g.identity

    # Agent identity
    agent_info = getattr(
        g,
        "agent_identity",
        None,
    )

    if agent_info:
        try:
            identity = ResolvedIdentity(
                identity_type=IdentityType.AGENT,
                tenant_id=agent_info["tenant_id"],
                org_id=agent_info["org_id"],
                subject_id=agent_info["agent_id"],
                role=Role.DEVELOPER,
                agent_name=agent_info.get(
                    "agent_name"
                ),
            )

            g.identity = identity
            return identity

        except Exception as exc:
            logger.warning(
                "agent_resolved_identity_failed",
                error=str(exc),
            )

    # Human session
    user = getattr(
        g,
        "authenticated_user",
        None,
    )

    if user:
        identity = _build_user_identity(user)

        if identity:
            g.user_identity = identity
            g.identity = identity
            return identity

    # Legacy global system key
    api_key = current_app.config.get("API_KEY")

    key = request.headers.get(
        "X-API-Key",
        "",
    ).strip()

    if (
        api_key
        and key
        and safe_compare(key, api_key)
    ):
        environment = current_app.config.get(
            "ENVIRONMENT",
            "development",
        )

        allow_legacy = current_app.config.get(
            "ALLOW_LEGACY_SYSTEM_KEY",
            False,
        )

        if (
            environment == "production"
            and not allow_legacy
        ):
            return None

        try:
            identity = ResolvedIdentity(
                identity_type=IdentityType.SYSTEM,
                tenant_id="default",
                org_id="default",
                subject_id="system_legacy_key",
                role=Role.ADMIN,
            )

            g.identity = identity
            return identity

        except Exception:
            return None

    return None


# ═══════════════════════════════════════════════════════════════
# RESOURCE AUTHORIZATION
# ═══════════════════════════════════════════════════════════════

def authorize_resource_access(
    target_tenant_id: str,
    target_org_id: Optional[str] = None,
    allow_cross_org: bool = False,
) -> bool:
    try:
        from identity import (
            IdentityType,
            Role,
        )
    except ImportError:
        return False

    identity = resolve_full_identity()

    if not identity:
        return False

    if identity.identity_type == IdentityType.SYSTEM:
        return True

    if identity.tenant_id != target_tenant_id:
        logger.warning(
            "authz_denied_cross_tenant",
            actor_tenant=identity.tenant_id,
            target_tenant=target_tenant_id,
        )
        return False

    if target_org_id is None:
        return identity.role == Role.ADMIN

    if identity.role == Role.ADMIN:
        return True

    if not allow_cross_org:
        return identity.org_id == target_org_id

    return True


# ═══════════════════════════════════════════════════════════════
# RBAC
# ═══════════════════════════════════════════════════════════════

def require_role(*required_roles: str):
    try:
        from identity import Role

        required = [
            Role(r)
            for r in required_roles
        ]

    except (ImportError, ValueError):
        required = []

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not require_auth():
                return jsonify(
                    {"error": "Unauthorized"}
                ), 401

            if not required:
                return func(*args, **kwargs)

            identity = resolve_full_identity()

            if not identity:
                return jsonify(
                    {"error": "Identity not resolved"}
                ), 401

            for role in required:
                try:
                    if identity.has_role(role):
                        return func(
                            *args,
                            **kwargs,
                        )
                except Exception:
                    if identity.role == role:
                        return func(
                            *args,
                            **kwargs,
                        )

            return jsonify(
                {
                    "error": "Forbidden",
                    "required_roles": [
                        r.value
                        if hasattr(r, "value")
                        else str(r)
                        for r in required
                    ],
                    "your_role": (
                        identity.role.value
                        if hasattr(
                            identity.role,
                            "value",
                        )
                        else str(identity.role)
                    ),
                }
            ), 403

        return wrapper

    return decorator


def require_permission(permission: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not require_auth():
                return jsonify(
                    {"error": "Unauthorized"}
                ), 401

            identity = resolve_full_identity()

            if not identity:
                return jsonify(
                    {"error": "Identity not resolved"}
                ), 401

            try:
                from identity import role_has_permission

                if not role_has_permission(
                    identity.role,
                    permission,
                ):
                    return jsonify(
                        {
                            "error": "Forbidden",
                            "required_permission": permission,
                            "your_role": (
                                identity.role.value
                                if hasattr(
                                    identity.role,
                                    "value",
                                )
                                else str(
                                    identity.role
                                )
                            ),
                        }
                    ), 403

            except ImportError:
                pass

            return func(
                *args,
                **kwargs,
            )

        return wrapper

    return decorator


# ═══════════════════════════════════════════════════════════════
# AUTHENTICATION MIDDLEWARE
# ═══════════════════════════════════════════════════════════════

def require_auth():
    """
    Authenticate:
      1. Agent/platform API key
      2. Human magic-link session
      3. Legacy API-key session

    Human sessions populate:
      g.org_id
      g.authenticated_user
      g.user_identity
      g.identity
    """
    api_key = current_app.config.get("API_KEY")

    # ── API KEY ─────────────────────────────────────────────

    key = request.headers.get(
        "X-API-Key",
        "",
    ).strip()

    if key:
        # Explicitly reject global legacy key in production
        if (
            api_key
            and safe_compare(key, api_key)
        ):
            environment = current_app.config.get(
                "ENVIRONMENT",
                "development",
            )

            allow_legacy = current_app.config.get(
                "ALLOW_LEGACY_SYSTEM_KEY",
                False,
            )

            if (
                environment == "production"
                and not allow_legacy
            ):
                logger.warning(
                    "legacy_system_key_rejected_in_production",
                    ip=request.remote_addr,
                    endpoint=request.endpoint,
                )
                return False

        org_id = resolve_org_id(key)

        if org_id:
            g.org_id = org_id

            try:
                resolve_full_identity()
            except Exception as exc:
                logger.debug(
                    "identity_resolution_failed",
                    error=str(exc),
                )

            return True

    # ── HUMAN SESSION ───────────────────────────────────────

    auth_cookie = current_app.config.get(
        "AUTH_COOKIE",
        MAGIC_LINK_COOKIE,
    )

    cookie_value = request.cookies.get(
        auth_cookie,
        "",
    )

    user = _resolve_human_session(
        cookie_value
    )

    if user:
        g.authenticated_user = user
        g.org_id = user[1]

        try:
            resolve_full_identity()
        except Exception as exc:
            logger.debug(
                "human_identity_resolution_failed",
                error=str(exc),
            )

        return True

    # ── LEGACY API KEY SESSION ──────────────────────────────

    org_id = _session_org_id(
        cookie_value
    )

    if org_id:
        g.org_id = org_id

        try:
            resolve_full_identity()
        except Exception as exc:
            logger.debug(
                "legacy_identity_resolution_failed",
                error=str(exc),
            )

        return True

    return False


# ═══════════════════════════════════════════════════════════════
# AUDIT HELPERS
# ═══════════════════════════════════════════════════════════════

def _audit_login(
    success: bool,
    email: Optional[str] = None,
    org_id: str = "unknown",
    reason: Optional[str] = None,
):
    try:
        from collector.audit_routes import (
            AuditEventType,
            get_audit_log,
        )

        audit = get_audit_log()

        if not audit:
            return

        event_type = (
            AuditEventType.LOGIN_SUCCESS
            if success
            else AuditEventType.LOGIN_FAILED
        )

        details = {
            "method": "magic_link",
        }

        if reason:
            details["reason"] = reason

        audit.log_event(
            event_type=event_type,
            org_id=org_id,
            actor=(
                f"user:{email}"
                if email
                else "unknown"
            ),
            resource="dashboard",
            action=(
                "login"
                if success
                else "login_failed"
            ),
            details=details,
            risk_level=(
                "info"
                if success
                else "warning"
            ),
        )

    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════
# LOGIN PAGE
# ═══════════════════════════════════════════════════════════════

LOGIN_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">
<title>Cerbere — Sign in</title>

<style>
:root {
    color-scheme: dark;
    --bg: #050b14;
    --card: #0b1626;
    --border: #1d3047;
    --text: #edf5ff;
    --muted: #8da2ba;
    --accent: #38bdf8;
    --accent2: #2563eb;
    --danger: #fb7185;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;
    display: grid;
    place-items: center;
    background:
        radial-gradient(
            circle at 50% 10%,
            #102d4c 0%,
            var(--bg) 58%
        );
    color: var(--text);
    font-family:
        Inter,
        ui-sans-serif,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}

.wrap {
    width: min(440px, 92vw);
}

.brand {
    text-align: center;
    margin-bottom: 28px;
}

.logo {
    width: 58px;
    height: 58px;
    margin: 0 auto 16px;
    display: grid;
    place-items: center;
    border-radius: 17px;
    background:
        linear-gradient(
            135deg,
            var(--accent2),
            var(--accent)
        );
    box-shadow:
        0 14px 45px
        rgba(37,99,235,.28);
    font-size: 28px;
}

h1 {
    margin: 0;
    font-size: 25px;
    letter-spacing: -.02em;
}

.subtitle {
    margin-top: 8px;
    color: var(--muted);
    font-size: 14px;
}

.card {
    padding: 30px;
    border:
        1px solid var(--border);
    border-radius: 20px;
    background:
        rgba(11,22,38,.96);
    box-shadow:
        0 24px 70px
        rgba(0,0,0,.35);
}

label {
    display: block;
    margin-bottom: 9px;
    font-size: 13px;
    font-weight: 650;
}

input {
    width: 100%;
    height: 50px;
    padding: 0 14px;
    border:
        1px solid #29415c;
    border-radius: 11px;
    outline: none;
    background: #07111f;
    color: var(--text);
    font: inherit;
}

input:focus {
    border-color: var(--accent);
    box-shadow:
        0 0 0 3px
        rgba(56,189,248,.10);
}

button {
    width: 100%;
    height: 50px;
    margin-top: 16px;
    border: 0;
    border-radius: 11px;
    background:
        linear-gradient(
            135deg,
            var(--accent2),
            var(--accent)
        );
    color: white;
    font: inherit;
    font-weight: 700;
    cursor: pointer;
}

button:hover {
    filter: brightness(1.07);
}

.hint {
    margin-top: 16px;
    color: var(--muted);
    font-size: 12px;
    line-height: 1.55;
    text-align: center;
}

.error {
    margin-bottom: 16px;
    padding: 11px 13px;
    border:
        1px solid
        rgba(251,113,133,.35);
    border-radius: 10px;
    background:
        rgba(127,29,29,.20);
    color: #fecdd3;
    font-size: 13px;
    line-height: 1.45;
}

.success {
    margin-bottom: 16px;
    padding: 11px 13px;
    border:
        1px solid
        rgba(56,189,248,.30);
    border-radius: 10px;
    background:
        rgba(14,116,144,.14);
    color: #bae6fd;
    font-size: 13px;
    line-height: 1.45;
}
</style>
</head>

<body>
<main class="wrap">

<div class="brand">
    <div class="logo">🛡️</div>
    <h1>Cerbere</h1>
    <div class="subtitle">
        AI Runtime Security Console
    </div>
</div>

<section class="card">

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

{% if success %}
<div class="success">{{ success }}</div>
{% endif %}

<form method="post" action="/login">

<label for="email">
    Work email
</label>

<input
    id="email"
    name="email"
    type="email"
    autocomplete="email"
    placeholder="you@company.com"
    required
    autofocus
>

<button type="submit">
    Send secure sign-in link
</button>

</form>

<div class="hint">
    We'll send a single-use sign-in link to your
    work email. The link expires in 10 minutes.
</div>

</section>
</main>
</body>
</html>
"""


# ═══════════════════════════════════════════════════════════════
# AUTH MIDDLEWARE HOOK
# ═══════════════════════════════════════════════════════════════

@auth_bp.before_app_request
def check_auth():
    if request.method == "OPTIONS":
        return None

    public_endpoints = {
        "auth.login",
        "auth.healthz",
        "auth.auth_login",
        "auth.verify_magic_link",
        "auth.logout",
    }

    if request.endpoint in public_endpoints:
        return None

    if request.endpoint not in PROTECTED_ENDPOINTS:
        return None

    try:
        if not require_auth():
            if request.endpoint in {
                "auth.dashboard",
                "trace.trace_detail",
            }:
                return redirect(
                    url_for("auth.login")
                )

            return jsonify(
                {
                    "error": "Unauthorized"
                }
            ), 401

    except Exception as exc:
        logger.error(
            "auth_middleware_error",
            error=str(exc),
        )

        return jsonify(
            {
                "error": "Unauthorized"
            }
        ), 401


# ═══════════════════════════════════════════════════════════════
# LOGIN — MAGIC LINK
# ═══════════════════════════════════════════════════════════════

@auth_bp.route(
    "/login",
    methods=["GET", "POST"],
)
def login():
    if request.method == "GET":
        return render_template_string(
            LOGIN_HTML,
            error=None,
            success=None,
        )

    if not MAGIC_LINK_ENABLED:
        return render_template_string(
            LOGIN_HTML,
            error="Passwordless login is currently disabled.",
            success=None,
        ), 503

    email = _normalize_email(
        request.form.get("email", "")
    )

    if not _valid_email(email):
        return render_template_string(
            LOGIN_HTML,
            error="Enter a valid work email address.",
            success=None,
        ), 400

    try:
        _ensure_magic_link_table()

        user = _user_by_email(email)

        # Do not reveal whether an email belongs to an account.
        if not user:
            logger.info(
                "magic_link_requested_unknown_email",
                email_domain=email.split("@", 1)[-1],
                ip=request.remote_addr,
            )

            return render_template_string(
                LOGIN_HTML,
                error=None,
                success=(
                    "If an account exists for this email, "
                    "a secure sign-in link has been sent."
                ),
            )

        if not bool(user[6]):
            logger.warning(
                "magic_link_requested_inactive_user",
                user_id=user[0],
                ip=request.remote_addr,
            )

            return render_template_string(
                LOGIN_HTML,
                error=None,
                success=(
                    "If an account exists for this email, "
                    "a secure sign-in link has been sent."
                ),
            )

        user_id = user[0]

        # Invalidate previous links.
        _invalidate_existing_magic_links(
            user_id
        )

        raw_token = secrets.token_urlsafe(
            MAGIC_LINK_TOKEN_BYTES
        )

        token_hash = _hash_magic_token(
            raw_token
        )

        expires_at = (
            _utcnow()
            + timedelta(
                seconds=MAGIC_LINK_TTL_SECONDS
            )
        )

        _store_magic_link(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
        )

        link = _build_magic_link(
            raw_token
        )

        _send_magic_link_email(
            email,
            link,
        )

        logger.info(
            "magic_link_requested",
            user_id=user_id,
            org_id=user[1],
            ip=request.remote_addr,
        )

        return render_template_string(
            LOGIN_HTML,
            error=None,
            success=(
                "Check your inbox. "
                "Your secure sign-in link expires in "
                "10 minutes."
            ),
        )

    except Exception as exc:
        logger.error(
            "magic_link_request_failed",
            error=str(exc),
        )

        return render_template_string(
            LOGIN_HTML,
            error=(
                "Unable to send the sign-in link. "
                "Please try again."
            ),
            success=None,
        ), 500


# ═══════════════════════════════════════════════════════════════
# MAGIC LINK VERIFY
# ═══════════════════════════════════════════════════════════════

@auth_bp.get("/auth/verify")
def verify_magic_link():
    token = str(
        request.args.get(
            "token",
            "",
        )
    ).strip()

    if not token:
        return render_template_string(
            LOGIN_HTML,
            error="Invalid or expired sign-in link.",
            success=None,
        ), 400

    try:
        _ensure_magic_link_table()

        user = _consume_magic_link(
            token
        )

        if not user:
            _audit_login(
                success=False,
                reason="invalid_or_expired_magic_link",
            )

            return render_template_string(
                LOGIN_HTML,
                error=(
                    "This sign-in link is invalid, "
                    "expired, or has already been used."
                ),
                success=None,
            ), 401

        user_id = user[0]
        org_id = user[1]
        email = user[3]

        response = redirect(
            url_for("auth.dashboard")
        )

        _set_human_session(
            response,
            user_id,
        )

        g.authenticated_user = user
        g.org_id = org_id

        _audit_login(
            success=True,
            email=email,
            org_id=org_id,
        )

        logger.info(
            "magic_link_login_success",
            user_id=user_id,
            org_id=org_id,
            ip=request.remote_addr,
        )

        return response

    except Exception as exc:
        logger.error(
            "magic_link_verification_failed",
            error=str(exc),
        )

        return render_template_string(
            LOGIN_HTML,
            error="Unable to verify the sign-in link.",
            success=None,
        ), 500


# ═══════════════════════════════════════════════════════════════
# JSON AUTH API
# ═══════════════════════════════════════════════════════════════

@auth_bp.post("/api/auth-login")
def auth_login():
    """
    JSON authentication endpoint.

    Preferred:
        {"email": "user@company.com"}

    Legacy compatibility:
        {"api_key": "..."}
    """
    data = request.get_json(
        silent=True
    ) or {}

    email = _normalize_email(
        data.get("email", "")
    )

    # ── Magic link ──────────────────────────────────────────

    if email:
        if not MAGIC_LINK_ENABLED:
            return jsonify(
                {
                    "error":
                    "Magic-link authentication disabled"
                }
            ), 503

        if not _valid_email(email):
            return jsonify(
                {
                    "error":
                    "Invalid email address"
                }
            ), 400

        try:
            _ensure_magic_link_table()

            user = _user_by_email(email)

            if user and bool(user[6]):
                user_id = user[0]

                _invalidate_existing_magic_links(
                    user_id
                )

                raw_token = secrets.token_urlsafe(
                    MAGIC_LINK_TOKEN_BYTES
                )

                _store_magic_link(
                    user_id=user_id,
                    token_hash=_hash_magic_token(
                        raw_token
                    ),
                    expires_at=(
                        _utcnow()
                        + timedelta(
                            seconds=MAGIC_LINK_TTL_SECONDS
                        )
                    ),
                )

                link = _build_magic_link(
                    raw_token
                )

                _send_magic_link_email(
                    email,
                    link,
                )

                logger.info(
                    "magic_link_api_requested",
                    user_id=user_id,
                    org_id=user[1],
                    ip=request.remote_addr,
                )

            return jsonify(
                {
                    "status": "ok",
                    "message": (
                        "If an account exists for this "
                        "email, a secure sign-in link "
                        "has been sent."
                    ),
                }
            ), 200

        except Exception as exc:
            logger.error(
                "magic_link_api_failed",
                error=str(exc),
            )

            return jsonify(
                {
                    "error":
                    "Unable to process sign-in request"
                }
            ), 500

    # ── Legacy API key compatibility ───────────────────────

    key = str(
        data.get(
            "api_key",
            "",
        )
    ).strip()

    if not key:
        return jsonify(
            {
                "error":
                "Email is required"
            }
        ), 400

    org_id = resolve_org_id(key)

    if not org_id:
        return jsonify(
            {
                "error":
                "Unauthorized"
            }
        ), 401

    if (
        org_id == "default"
        and current_app.config.get(
            "ENVIRONMENT"
        ) == "production"
        and not current_app.config.get(
            "ALLOW_LEGACY_SYSTEM_KEY",
            False,
        )
    ):
        return jsonify(
            {
                "error":
                "Legacy system API key disabled"
            }
        ), 401

    response = jsonify(
        {
            "status": "ok",
            "org_id": org_id,
        }
    )

    cookie_name = current_app.config.get(
        "AUTH_COOKIE",
        MAGIC_LINK_COOKIE,
    )

    response.set_cookie(
        cookie_name,
        _session_token(
            org_id,
            hash_key(key),
        ),
        httponly=True,
        secure=bool(
            getattr(
                current_app,
                "auth_cookie_secure",
                True,
            )
        ),
        samesite="Lax",
        max_age=current_app.config.get(
            "AUTH_SESSION_TTL",
            3600,
        ),
        path="/",
    )

    return response


# ═══════════════════════════════════════════════════════════════
# CURRENT USER
# ═══════════════════════════════════════════════════════════════

@auth_bp.get("/api/auth/me")
def auth_me():
    if not require_auth():
        return jsonify(
            {
                "authenticated": False
            }
        ), 401

    identity = resolve_full_identity()

    user = getattr(
        g,
        "authenticated_user",
        None,
    )

    if user:
        return jsonify(
            {
                "authenticated": True,
                "type": "human",
                "user": {
                    "user_id": user[0],
                    "org_id": user[1],
                    "tenant_id": user[2],
                    "email": user[3],
                    "display_name": user[4],
                    "role": user[5],
                },
            }
        ), 200

    return jsonify(
        {
            "authenticated": True,
            "type": (
                "agent"
                if getattr(
                    g,
                    "agent_identity",
                    None,
                )
                else "api_key"
            ),
            "org_id": getattr(
                g,
                "org_id",
                None,
            ),
            "identity": (
                identity.to_dict()
                if identity
                and hasattr(
                    identity,
                    "to_dict",
                )
                else None
            ),
        }
    ), 200


# ═══════════════════════════════════════════════════════════════
# LOGOUT
# ═══════════════════════════════════════════════════════════════

@auth_bp.route(
    "/logout",
    methods=["GET", "POST"],
)
def logout():
    response = redirect(
        url_for("auth.login")
    )

    _clear_human_session(
        response
    )

    logger.info(
        "logout",
        ip=request.remote_addr,
    )

    return response


# ═══════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════════

@auth_bp.get("/healthz")
def healthz():
    try:
        from collector.db import get_db

        conn = get_db()

        try:
            if is_postgres():
                cur = conn.cursor()
                cur.execute("SELECT 1")
                cur.fetchone()
            else:
                conn.execute("SELECT 1")
        finally:
            conn.close()

        return jsonify(
            {
                "status": "ok"
            }
        ), 200

    except Exception as exc:
        return jsonify(
            {
                "status": "degraded",
                "error": str(exc)[:120],
            }
        ), 503


# ═══════════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════════

@auth_bp.route("/")
def dashboard():
    from collector.dashboard import DASHBOARD_HTML
    from flask import make_response

    return make_response(
        render_template_string(
            DASHBOARD_HTML
        )
    )
