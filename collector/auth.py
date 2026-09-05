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
# LOGIN PAGE (Professional, Enterprise-Grade, No Emojis)
# ═══════════════════════════════════════════════════════════════

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cerbere — Secure Access</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg-primary: #09090b;
            --bg-secondary: #18181b;
            --bg-card: rgba(24, 24, 27, 0.6);
            --border-color: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(239, 68, 68, 0.5);
            --text-primary: #fafafa;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
            --accent-glow: rgba(239, 68, 68, 0.15);
            --success: #10b981;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
            -webkit-font-smoothing: antialiased;
        }

        .container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            min-height: 100vh;
        }

        .login-section {
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            padding: 3rem;
            background: var(--bg-primary);
            position: relative;
        }

        .login-container {
            width: 100%;
            max-width: 420px;
            position: relative;
            z-index: 1;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 2.5rem;
        }

        .logo img {
            width: 40px;
            height: 40px;
        }

        .logo-text {
            font-size: 22px;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: var(--text-primary);
        }

        .welcome-text {
            margin-bottom: 2rem;
        }

        .welcome-text h1 {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 0.5rem;
            letter-spacing: -0.02em;
            color: var(--text-primary);
        }

        .welcome-text p {
            color: var(--text-secondary);
            font-size: 15px;
            line-height: 1.5;
        }

        .auth-tabs {
            display: flex;
            gap: 4px;
            margin-bottom: 2rem;
            background: rgba(255, 255, 255, 0.03);
            padding: 4px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }

        .auth-tab {
            flex: 1;
            padding: 10px 16px;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            border-radius: 6px;
            transition: all 0.2s ease;
        }

        .auth-tab.active {
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-primary);
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
        }

        .auth-tab:hover:not(.active) {
            color: var(--text-primary);
        }

        .auth-form {
            display: none;
            animation: fadeIn 0.3s ease;
        }

        .auth-form.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .form-group {
            margin-bottom: 1.25rem;
        }

        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-size: 13px;
            font-weight: 500;
            color: var(--text-secondary);
        }

        .form-group input {
            width: 100%;
            padding: 12px 14px;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 14px;
            transition: all 0.2s ease;
            outline: none;
        }

        .form-group input:focus {
            border-color: var(--border-hover);
            background: rgba(255, 255, 255, 0.05);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }

        .form-group input::placeholder {
            color: var(--text-muted);
        }

        .btn-primary {
            width: 100%;
            padding: 12px;
            background: var(--text-primary);
            border: none;
            border-radius: 8px;
            color: var(--bg-primary);
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .btn-primary:hover {
            background: #e4e4e7;
        }

        .btn-primary:active {
            transform: scale(0.98);
        }

        .divider {
            display: flex;
            align-items: center;
            margin: 1.5rem 0;
            color: var(--text-muted);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .divider::before,
        .divider::after {
            content: '';
            flex: 1;
            height: 1px;
            background: var(--border-color);
        }

        .divider span {
            padding: 0 1rem;
        }

        .social-buttons {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-bottom: 1.5rem;
        }

        .social-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 12px;
            background: transparent;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
        }

        .social-btn:hover {
            background: rgba(255, 255, 255, 0.05);
            border-color: var(--text-muted);
        }

        .social-btn svg {
            width: 18px;
            height: 18px;
        }

        .signup-link {
            text-align: center;
            margin-top: 1.5rem;
            color: var(--text-secondary);
            font-size: 14px;
        }

        .signup-link a {
            color: var(--text-primary);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s ease;
        }

        .signup-link a:hover {
            text-decoration: underline;
        }

        .security-badge {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            margin-top: 2rem;
            padding: 10px;
            background: rgba(16, 185, 129, 0.05);
            border: 1px solid rgba(16, 185, 129, 0.15);
            border-radius: 6px;
            color: var(--success);
            font-size: 12px;
            font-weight: 500;
            letter-spacing: 0.02em;
        }

        .security-badge::before {
            content: '';
            width: 6px;
            height: 6px;
            background: var(--success);
            border-radius: 50%;
            box-shadow: 0 0 8px var(--success);
            animation: pulse-dot 2s infinite;
        }

        @keyframes pulse-dot {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }

        .alert {
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 14px;
            margin-bottom: 1.5rem;
            line-height: 1.5;
            animation: fadeIn 0.3s ease;
        }

        .alert-error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: #f87171;
        }

        .alert-success {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            color: #34d399;
        }

        .hero-section {
            position: relative;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            padding: 3rem;
            background: var(--bg-secondary);
            overflow: hidden;
            border-left: 1px solid var(--border-color);
        }

        .hero-bg {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            overflow: hidden;
        }

        .wave-container {
            position: absolute;
            width: 100%;
            height: 100%;
        }

        .wave {
            position: absolute;
            width: 150%;
            height: 150%;
            top: -25%;
            left: -25%;
            background: radial-gradient(circle, rgba(239, 68, 68, 0.08) 0%, transparent 60%);
            border-radius: 40%;
            animation: rotate 30s linear infinite;
            transition: transform 0.1s ease-out;
        }

        .wave:nth-child(2) {
            background: radial-gradient(circle, rgba(249, 115, 22, 0.06) 0%, transparent 60%);
            animation-delay: -10s;
            animation-duration: 40s;
        }

        .wave:nth-child(3) {
            background: radial-gradient(circle, rgba(239, 68, 68, 0.04) 0%, transparent 60%);
            animation-delay: -20s;
            animation-duration: 50s;
        }

        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        .grid-overlay {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: 
                linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
            background-size: 40px 40px;
            mask-image: radial-gradient(circle at center, black 40%, transparent 80%);
            -webkit-mask-image: radial-gradient(circle at center, black 40%, transparent 80%);
        }

        .hero-content {
            position: relative;
            z-index: 1;
            text-align: center;
            max-width: 560px;
        }

        .hero-logo {
            width: 80px;
            height: 80px;
            margin-bottom: 2rem;
            filter: drop-shadow(0 0 40px rgba(239, 68, 68, 0.2));
            transition: transform 0.5s ease;
        }

        .hero-section:hover .hero-logo {
            transform: scale(1.05);
        }

        .hero-title {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 1rem;
            line-height: 1.2;
            letter-spacing: -0.02em;
            color: var(--text-primary);
        }

        .hero-title span {
            background: linear-gradient(135deg, var(--accent-red) 0%, var(--accent-orange) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .hero-subtitle {
            font-size: 16px;
            color: var(--text-secondary);
            line-height: 1.6;
            margin-bottom: 3rem;
        }

        .hero-features {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            text-align: left;
        }

        .feature {
            padding: 16px;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        .feature:hover {
            border-color: rgba(239, 68, 68, 0.3);
            background: rgba(255, 255, 255, 0.04);
        }

        .feature-icon {
            width: 32px;
            height: 32px;
            margin-bottom: 12px;
            color: var(--accent-red);
        }

        .feature h3 {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 4px;
            color: var(--text-primary);
        }

        .feature p {
            font-size: 13px;
            color: var(--text-muted);
            line-height: 1.4;
        }

        @media (max-width: 968px) {
            .container {
                grid-template-columns: 1fr;
            }
            .hero-section {
                display: none;
            }
            .login-section {
                padding: 2rem;
            }
        }

        @media (max-width: 480px) {
            .social-buttons {
                grid-template-columns: 1fr;
            }
            .hero-features {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- LEFT SIDE - LOGIN -->
        <section class="login-section">
            <div class="login-container">
                <div class="logo">
                    <img src="/static/logo.svg" alt="Cerbere Logo">
                    <span class="logo-text">CERBERE</span>
                </div>

                <div class="welcome-text">
                    <h1>Welcome back</h1>
                    <p>Secure access to your AI runtime security console.</p>
                </div>

                {% if error %}
                <div class="alert alert-error">
                    {{ error }}
                </div>
                {% endif %}

                {% if success %}
                <div class="alert alert-success">
                    {{ success }}
                </div>
                {% endif %}

                <div class="auth-tabs">
                    <button class="auth-tab active" onclick="switchTab('email')" id="tab-email">
                        Work Email
                    </button>
                    <button class="auth-tab" onclick="switchTab('sso')" id="tab-sso">
                        Enterprise SSO
                    </button>
                </div>

                <!-- Email Form -->
                <form class="auth-form active" id="email-form" method="post" action="/login">
                    <div class="form-group">
                        <label for="email">Work Email</label>
                        <input 
                            type="email" 
                            id="email" 
                            name="email" 
                            placeholder="name@company.com" 
                            required 
                            autocomplete="email"
                            autocapitalize="none"
                        >
                    </div>
                    <button type="submit" class="btn-primary" id="email-btn">
                        Send Magic Link
                    </button>
                </form>

                <!-- SSO Form -->
                <form class="auth-form" id="sso-form" method="post" action="/login">
                    <div class="form-group">
                        <label for="company-domain">Company Domain</label>
                        <input 
                            type="text" 
                            id="company-domain" 
                            name="domain" 
                            placeholder="company.com" 
                            required
                        >
                    </div>
                    <div class="form-group">
                        <label for="sso-email">Work Email</label>
                        <input 
                            type="email" 
                            id="sso-email" 
                            name="email" 
                            placeholder="name@company.com" 
                            required
                        >
                    </div>
                    <button type="submit" class="btn-primary" id="sso-btn">
                        Continue with SSO
                    </button>
                </form>

                <div class="divider">
                    <span>Or continue with</span>
                </div>

                <div class="social-buttons">
                    <a href="/auth/google" class="social-btn">
                        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                        </svg>
                        Google
                    </a>
                    <a href="/auth/github" class="social-btn">
                        <svg viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
                            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
                        </svg>
                        GitHub
                    </a>
                </div>

                <div class="signup-link">
                    Don't have an account? <a href="/signup">Sign up</a>
                </div>

                <div class="security-badge">
                    SOC 2 Type II Compliant
                </div>
            </div>
        </section>

        <!-- RIGHT SIDE - HERO -->
        <section class="hero-section" id="hero-section">
            <div class="hero-bg">
                <div class="wave-container">
                    <div class="wave"></div>
                    <div class="wave"></div>
                    <div class="wave"></div>
                </div>
                <div class="grid-overlay"></div>
            </div>

            <div class="hero-content">
                <img src="/static/logo.svg" alt="Cerbere" class="hero-logo">
                <h1 class="hero-title">Cerbere &mdash; The Three-Headed <span>Guardian</span> of AI Agents</h1>
                <p class="hero-subtitle">
                    Advanced runtime security and observability for AI agents. 
                    Monitor, detect, and protect your AI infrastructure in real-time.
                </p>

                <div class="hero-features">
                    <div class="feature">
                        <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                        </svg>
                        <h3>Runtime Security</h3>
                        <p>Real-time threat detection and policy enforcement.</p>
                    </div>
                    <div class="feature">
                        <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                            <circle cx="12" cy="12" r="3"></circle>
                        </svg>
                        <h3>Observability</h3>
                        <p>Complete visibility into agent behavior and decisions.</p>
                    </div>
                    <div class="feature">
                        <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                        </svg>
                        <h3>Access Control</h3>
                        <p>Granular RBAC and audit trails for compliance.</p>
                    </div>
                    <div class="feature">
                        <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                        </svg>
                        <h3>Low Latency</h3>
                        <p>Sub-millisecond security checks without blocking.</p>
                    </div>
                </div>
            </div>
        </section>
    </div>

    <script>
        function switchTab(tab) {
            const tabs = document.querySelectorAll('.auth-tab');
            const forms = document.querySelectorAll('.auth-form');
            
            tabs.forEach(t => t.classList.remove('active'));
            forms.forEach(f => f.classList.remove('active'));
            
            if (tab === 'email') {
                document.getElementById('tab-email').classList.add('active');
                document.getElementById('email-form').classList.add('active');
            } else {
                document.getElementById('tab-sso').classList.add('active');
                document.getElementById('sso-form').classList.add('active');
            }
        }

        const heroSection = document.getElementById('hero-section');
        const waves = document.querySelectorAll('.wave');
        
        if (heroSection && waves.length > 0) {
            heroSection.addEventListener('mousemove', (e) => {
                const rect = heroSection.getBoundingClientRect();
                const x = (e.clientX - rect.left) / rect.width - 0.5;
                const y = (e.clientY - rect.top) / rect.height - 0.5;
                
                waves.forEach((wave, index) => {
                    const speed = (index + 1) * 15;
                    wave.style.transform = `translate(${x * speed}px, ${y * speed}px)`;
                });
            });

            heroSection.addEventListener('mouseleave', () => {
                waves.forEach(wave => {
                    wave.style.transform = 'translate(0, 0)';
                });
            });
        }
    </script>
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
        "auth.signup",
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
# SIGN UP PAGE
# ═══════════════════════════════════════════════════════════════

SIGNUP_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cerbere — Create Account</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* Mêmes variables et styles que la page de login pour une cohérence totale */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-primary: #09090b; --bg-secondary: #18181b;
            --border-color: rgba(255, 255, 255, 0.08); --border-hover: rgba(239, 68, 68, 0.5);
            --text-primary: #fafafa; --text-secondary: #a1a1aa; --text-muted: #71717a;
            --accent-red: #ef4444; --accent-orange: #f97316; --accent-glow: rgba(239, 68, 68, 0.15);
            --success: #10b981;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary); color: var(--text-primary);
            min-height: 100vh; overflow-x: hidden; -webkit-font-smoothing: antialiased;
        }
        .container { display: grid; grid-template-columns: 1fr 1fr; min-height: 100vh; }
        .login-section {
            display: flex; flex-direction: column; justify-content: center; align-items: center;
            padding: 3rem; background: var(--bg-primary); position: relative;
        }
        .login-container { width: 100%; max-width: 420px; position: relative; z-index: 1; }
        .logo { display: flex; align-items: center; gap: 12px; margin-bottom: 2.5rem; }
        .logo img { width: 40px; height: 40px; }
        .logo-text { font-size: 22px; font-weight: 700; letter-spacing: -0.02em; color: var(--text-primary); }
        .welcome-text { margin-bottom: 2rem; }
        .welcome-text h1 { font-size: 28px; font-weight: 600; margin-bottom: 0.5rem; letter-spacing: -0.02em; }
        .welcome-text p { color: var(--text-secondary); font-size: 15px; line-height: 1.5; }
        .form-group { margin-bottom: 1.25rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; font-size: 13px; font-weight: 500; color: var(--text-secondary); }
        .form-group input {
            width: 100%; padding: 12px 14px; background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary);
            font-size: 14px; transition: all 0.2s ease; outline: none;
        }
        .form-group input:focus {
            border-color: var(--border-hover); background: rgba(255, 255, 255, 0.05);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }
        .form-group input::placeholder { color: var(--text-muted); }
        .btn-primary {
            width: 100%; padding: 12px; background: var(--text-primary); border: none;
            border-radius: 8px; color: var(--bg-primary); font-size: 14px; font-weight: 600;
            cursor: pointer; transition: all 0.2s ease;
        }
        .btn-primary:hover { background: #e4e4e7; }
        .btn-primary:active { transform: scale(0.98); }
        .signup-link { text-align: center; margin-top: 1.5rem; color: var(--text-secondary); font-size: 14px; }
        .signup-link a { color: var(--text-primary); text-decoration: none; font-weight: 500; transition: color 0.2s ease; }
        .signup-link a:hover { text-decoration: underline; }
        .security-badge {
            display: flex; align-items: center; justify-content: center; gap: 8px;
            margin-top: 2rem; padding: 10px; background: rgba(16, 185, 129, 0.05);
            border: 1px solid rgba(16, 185, 129, 0.15); border-radius: 6px;
            color: var(--success); font-size: 12px; font-weight: 500; letter-spacing: 0.02em;
        }
        .security-badge::before {
            content: ''; width: 6px; height: 6px; background: var(--success);
            border-radius: 50%; box-shadow: 0 0 8px var(--success); animation: pulse-dot 2s infinite;
        }
        @keyframes pulse-dot { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        .alert { padding: 12px 16px; border-radius: 8px; font-size: 14px; margin-bottom: 1.5rem; line-height: 1.5; animation: fadeIn 0.3s ease; }
        .alert-error { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); color: #f87171; }
        .alert-success { background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); color: #34d399; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }
        
        /* Hero Section (identique à login) */
        .hero-section {
            position: relative; display: flex; flex-direction: column; justify-content: center;
            align-items: center; padding: 3rem; background: var(--bg-secondary);
            overflow: hidden; border-left: 1px solid var(--border-color);
        }
        .hero-bg { position: absolute; top: 0; left: 0; right: 0; bottom: 0; overflow: hidden; }
        .wave-container { position: absolute; width: 100%; height: 100%; }
        .wave {
            position: absolute; width: 150%; height: 150%; top: -25%; left: -25%;
            background: radial-gradient(circle, rgba(239, 68, 68, 0.08) 0%, transparent 60%);
            border-radius: 40%; animation: rotate 30s linear infinite; transition: transform 0.1s ease-out;
        }
        .wave:nth-child(2) { background: radial-gradient(circle, rgba(249, 115, 22, 0.06) 0%, transparent 60%); animation-delay: -10s; animation-duration: 40s; }
        .wave:nth-child(3) { background: radial-gradient(circle, rgba(239, 68, 68, 0.04) 0%, transparent 60%); animation-delay: -20s; animation-duration: 50s; }
        @keyframes rotate { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        .grid-overlay {
            position: absolute; top: 0; left: 0; right: 0; bottom: 0;
            background-image: linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
            background-size: 40px 40px; mask-image: radial-gradient(circle at center, black 40%, transparent 80%);
        }
        .hero-content { position: relative; z-index: 1; text-align: center; max-width: 560px; }
        .hero-logo { width: 80px; height: 80px; margin-bottom: 2rem; filter: drop-shadow(0 0 40px rgba(239, 68, 68, 0.2)); transition: transform 0.5s ease; }
        .hero-section:hover .hero-logo { transform: scale(1.05); }
        .hero-title { font-size: 36px; font-weight: 700; margin-bottom: 1rem; line-height: 1.2; letter-spacing: -0.02em; color: var(--text-primary); }
        .hero-title span { background: linear-gradient(135deg, var(--accent-red) 0%, var(--accent-orange) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
        .hero-subtitle { font-size: 16px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 3rem; }
        .hero-features { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; text-align: left; }
        .feature { padding: 16px; background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 8px; transition: all 0.3s ease; }
        .feature:hover { border-color: rgba(239, 68, 68, 0.3); background: rgba(255, 255, 255, 0.04); }
        .feature-icon { width: 32px; height: 32px; margin-bottom: 12px; color: var(--accent-red); }
        .feature h3 { font-size: 14px; font-weight: 600; margin-bottom: 4px; color: var(--text-primary); }
        .feature p { font-size: 13px; color: var(--text-muted); line-height: 1.4; }
        @media (max-width: 968px) { .container { grid-template-columns: 1fr; } .hero-section { display: none; } .login-section { padding: 2rem; } }
    </style>
</head>
<body>
    <div class="container">
        <section class="login-section">
            <div class="login-container">
                <div class="logo">
                    <img src="/static/logo.svg" alt="Cerbere Logo">
                    <span class="logo-text">CERBERE</span>
                </div>

                <div class="welcome-text">
                    <h1>Create your account</h1>
                    <p>Start securing your AI agents in minutes.</p>
                </div>

                {% if error %}
                <div class="alert alert-error">{{ error }}</div>
                {% endif %}

                {% if success %}
                <div class="alert alert-success">{{ success }}</div>
                {% endif %}

                <form class="auth-form active" method="post" action="/signup">
                    <div class="form-group">
                        <label for="name">Full Name</label>
                        <input type="text" id="name" name="name" placeholder="John Doe" required autocomplete="name">
                    </div>
                    <div class="form-group">
                        <label for="email">Work Email</label>
                        <input type="email" id="email" name="email" placeholder="name@company.com" required autocomplete="email" autocapitalize="none">
                    </div>
                    <div class="form-group">
                        <label for="company">Company Name <span style="color: var(--text-muted); font-weight: 400;">(Optional)</span></label>
                        <input type="text" id="company" name="company" placeholder="Acme Inc." autocomplete="organization">
                    </div>
                    <button type="submit" class="btn-primary">Create account & send link</button>
                </form>

                <div class="signup-link">
                    Already have an account? <a href="/login">Sign in</a>
                </div>

                <div class="security-badge">SOC 2 Type II Compliant</div>
            </div>
        </section>

        <section class="hero-section" id="hero-section">
            <div class="hero-bg">
                <div class="wave-container">
                    <div class="wave"></div><div class="wave"></div><div class="wave"></div>
                </div>
                <div class="grid-overlay"></div>
            </div>
            <div class="hero-content">
                <img src="/static/logo.svg" alt="Cerbere" class="hero-logo">
                <h1 class="hero-title">Cerbere &mdash; The Three-Headed <span>Guardian</span> of AI Agents</h1>
                <p class="hero-subtitle">Advanced runtime security and observability for AI agents. Monitor, detect, and protect your AI infrastructure in real-time.</p>
                <div class="hero-features">
                    <div class="feature">
                        <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                        <h3>Runtime Security</h3><p>Real-time threat detection and policy enforcement.</p>
                    </div>
                    <div class="feature">
                        <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                        <h3>Observability</h3><p>Complete visibility into agent behavior and decisions.</p>
                    </div>
                    <div class="feature">
                        <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                        <h3>Access Control</h3><p>Granular RBAC and audit trails for compliance.</p>
                    </div>
                    <div class="feature">
                        <svg class="feature-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                        <h3>Low Latency</h3><p>Sub-millisecond security checks without blocking.</p>
                    </div>
                </div>
            </div>
        </section>
    </div>
    <script>
        const heroSection = document.getElementById('hero-section');
        const waves = document.querySelectorAll('.wave');
        if (heroSection && waves.length > 0) {
            heroSection.addEventListener('mousemove', (e) => {
                const rect = heroSection.getBoundingClientRect();
                const x = (e.clientX - rect.left) / rect.width - 0.5;
                const y = (e.clientY - rect.top) / rect.height - 0.5;
                waves.forEach((wave, index) => {
                    const speed = (index + 1) * 15;
                    wave.style.transform = `translate(${x * speed}px, ${y * speed}px)`;
                });
            });
            heroSection.addEventListener('mouseleave', () => {
                waves.forEach(wave => { wave.style.transform = 'translate(0, 0)'; });
            });
        }
    </script>
</body>
</html>
"""


@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template_string(SIGNUP_HTML, error=None, success=None)

    email = _normalize_email(request.form.get("email", ""))
    display_name = request.form.get("name", "").strip()
    company_name = request.form.get("company", "").strip()
    
    if not _valid_email(email):
        return render_template_string(SIGNUP_HTML, error="Enter a valid work email address.", success=None), 400
    
    if not display_name:
        return render_template_string(SIGNUP_HTML, error="Full name is required.", success=None), 400

    try:
        _ensure_magic_link_table()
        
        # 1. Vérifier si l'utilisateur existe déjà
        existing_user = _user_by_email(email)
        if existing_user:
            return render_template_string(
                SIGNUP_HTML, 
                error="An account with this email already exists. Please log in.", 
                success=None
            ), 400

        # 2. Générer les identifiants uniques pour la chaîne Tenant -> Org -> User
        user_id = str(uuid.uuid4())
        org_id = str(uuid.uuid4())
        tenant_id = str(uuid.uuid4()) # On crée un nouveau tenant dédié pour cet inscrit
        
        tenant_name = company_name or f"{display_name}'s Workspace"
        org_name = company_name or "Default Organization"

        # 3. Insérer dans l'ordre des contraintes de clé étrangère (Foreign Keys)
        if is_postgres():
            conn = get_pg_conn()
            try:
                cur = conn.cursor()
                
                # Étape A : Créer le Tenant
                cur.execute("""
                    INSERT INTO tenants (tenant_id, name, created_at)
                    VALUES (%s, %s, CURRENT_TIMESTAMP)
                """, (tenant_id, tenant_name))
                
                # Étape B : Créer l'Organisation liée à ce Tenant
                cur.execute("""
                    INSERT INTO orgs (org_id, tenant_id, name, created_at)
                    VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                """, (org_id, tenant_id, org_name))
                
                # Étape C : Créer l'Utilisateur lié à ce Tenant et cette Organisation
                cur.execute("""
                    INSERT INTO users (user_id, org_id, tenant_id, email, display_name, role, active, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                """, (user_id, org_id, tenant_id, email, display_name, "admin", True))
                
                conn.commit()
            finally:
                conn.close()
        else:
            # Fallback SQLite pour le développement local
            conn = sqlite3.connect(_get_db_path())
            try:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO tenants (tenant_id, name, created_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                """, (tenant_id, tenant_name))
                
                cur.execute("""
                    INSERT INTO orgs (org_id, tenant_id, name, created_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (org_id, tenant_id, org_name))
                
                cur.execute("""
                    INSERT INTO users (user_id, org_id, tenant_id, email, display_name, role, active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (user_id, org_id, tenant_id, email, display_name, "admin", 1))
                conn.commit()
            finally:
                conn.close()

        # 4. Générer et envoyer automatiquement le Magic Link pour une connexion immédiate
        raw_token = secrets.token_urlsafe(MAGIC_LINK_TOKEN_BYTES)
        token_hash = _hash_magic_token(raw_token)
        expires_at = _utcnow() + timedelta(seconds=MAGIC_LINK_TTL_SECONDS)

        _store_magic_link(user_id=user_id, token_hash=token_hash, expires_at=expires_at)
        link = _build_magic_link(raw_token)
        _send_magic_link_email(email, link)

        logger.info(
            "user_registered_and_magic_link_sent", 
            user_id=user_id, 
            email=email,
            ip=request.remote_addr,
        )

        return render_template_string(
            SIGNUP_HTML,
            error=None,
            success="Account created successfully! A secure sign-in link has been sent to your email."
        )

    except Exception as exc:
        logger.error("signup_failed", error=str(exc), email=email)
        return render_template_string(
            SIGNUP_HTML, 
            error="Unable to create account. Please try again.", 
            success=None
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
