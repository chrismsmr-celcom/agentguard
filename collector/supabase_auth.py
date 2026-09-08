"""
Supabase Auth — vérification JWT + auto-provisioning.

Remplace l'envoi d'email fait à la main (smtplib) par Supabase :
  - Magic link email  -> supabase.auth.signInWithOtp() côté front
  - Google OAuth       -> supabase.auth.signInWithOAuth({provider:'google'})
  - GitHub OAuth        -> supabase.auth.signInWithOAuth({provider:'github'})

Supabase gère l'envoi d'email et le flow OAuth. Ce module ne fait que
DEUX choses côté serveur, sans rien changer au modèle multi-tenant
existant (tenants / orgs / users avec role, déjà utilisé par
require_role / require_permission / authorize_resource_access) :

  1. Vérifier le JWT émis par Supabase (HS256, secret de projet —
     aucun appel réseau requis, contrairement à la vérification via
     JWKS/RS256).
  2. Provisionner paresseusement (tenant, org, user) au premier login
     d'un supabase_user_id encore inconnu — exactement la même logique
     que l'ancien /signup, mais déclenchée automatiquement au lieu
     d'un formulaire séparé.

Le cookie de session humaine (_set_human_session dans collector/auth.py)
et tout le reste (RBAC, audit, dashboard) restent INCHANGÉS : ce module
se contente de produire le même tuple `user` à 7 colonnes que
_user_by_email/_user_by_id, pour que _build_user_identity() continue
de fonctionner sans modification.

Config requise (Supabase Dashboard > Project Settings > API) :
    AGENTGUARD_SUPABASE_URL=https://xxxxx.supabase.co
    AGENTGUARD_SUPABASE_ANON_KEY=eyJ...        (publique, utilisée côté front)
    AGENTGUARD_SUPABASE_JWT_SECRET=...         (secrète, JAMAIS exposée au front)
"""
import os
import sqlite3
import uuid
from typing import Optional

import requests
import structlog

from collector.db import _get_db_path, get_pg_conn, get_sqlite_conn, is_postgres

logger = structlog.get_logger("agentguard.supabase_auth")

SUPABASE_URL = os.environ.get("AGENTGUARD_SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_ANON_KEY = os.environ.get("AGENTGUARD_SUPABASE_ANON_KEY", "").strip()

# NOTE : AGENTGUARD_SUPABASE_JWT_SECRET n'est PLUS utilisé pour vérifier la
# signature localement. Les projets Supabase créés avec le nouveau système
# "JWT Signing Keys" (rotation de clés, chaque token porte un `kid`) rendent
# le secret HS256 statique de Settings > API > JWT Secret obsolète dès la
# première rotation -> tous les logins échouent avec "Signature verification
# failed" alors que le token est parfaitement valide. On délègue donc la
# vérification à Supabase lui-même via /auth/v1/user, qui reste correct quel
# que soit le système de clés utilisé côté projet (legacy HS256 statique ou
# nouvelles signing keys).
SUPABASE_ENABLED = bool(SUPABASE_URL and SUPABASE_ANON_KEY)


class SupabaseAuthError(Exception):
    pass


def verify_supabase_jwt(token: str) -> dict:
    """
    Fait vérifier l'access_token par Supabase lui-même (GET /auth/v1/user)
    plutôt qu'une vérification de signature locale. Lève SupabaseAuthError
    si le token est invalide, expiré, ou révoqué.

    Retourne un payload dans le même format que l'ancien decode JWT local :
    sub (= user_id Supabase), email, user_metadata, app_metadata — pour ne
    rien changer à get_or_provision_user().
    """
    if not SUPABASE_ENABLED:
        raise SupabaseAuthError("Supabase URL/anon key non configurés")

    try:
        resp = requests.get(
            f"{SUPABASE_URL}/auth/v1/user",
            headers={
                "Authorization": f"Bearer {token}",
                "apikey": SUPABASE_ANON_KEY,
            },
            timeout=5.0,
        )
    except requests.RequestException as exc:
        raise SupabaseAuthError(f"Supabase injoignable : {exc}")

    if resp.status_code != 200:
        raise SupabaseAuthError(
            f"token Supabase invalide (HTTP {resp.status_code})"
        )

    data = resp.json()
    user_id = data.get("id")
    if not user_id:
        raise SupabaseAuthError("réponse Supabase sans user id")

    return {
        "sub": user_id,
        "email": data.get("email", ""),
        "user_metadata": data.get("user_metadata") or {},
        "app_metadata": data.get("app_metadata") or {},
    }


def _db_execute(query: str, params=(), fetchone=False, fetchall=False):
    if is_postgres():
        conn = get_pg_conn()
    else:
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


def _user_by_supabase_id(supabase_user_id: str):
    """
    users.supabase_user_id doit être ajouté à la table users
    (migration ci-dessous) pour lier un user Supabase à ta ligne
    tenant/org/role existante.
    """
    ph = "%s" if is_postgres() else "?"
    return _db_execute(
        f"""
        SELECT user_id, org_id, tenant_id, email, display_name, role, active
        FROM users
        WHERE supabase_user_id = {ph}
        LIMIT 1
        """,
        (supabase_user_id,),
        fetchone=True,
    )


def _ensure_supabase_column():
    """Migration défensive : ajoute users.supabase_user_id si absent."""
    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                ALTER TABLE users
                ADD COLUMN IF NOT EXISTS supabase_user_id TEXT UNIQUE
                """
            )
            conn.commit()
        finally:
            conn.close()
        return

    # SQLite : pas d'IF NOT EXISTS pour ADD COLUMN, on vérifie à la main.
    conn = sqlite3.connect(_get_db_path())
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(users)")
        cols = {row[1] for row in cur.fetchall()}
        if "supabase_user_id" not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN supabase_user_id TEXT")
            cur.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS "
                "idx_users_supabase_id ON users(supabase_user_id)"
            )
        conn.commit()
    finally:
        conn.close()


def get_or_provision_user(payload: dict):
    """
    Retourne le tuple `user` (user_id, org_id, tenant_id, email,
    display_name, role, active) — en le créant au premier login si
    ce supabase_user_id n'existe pas encore.

    Le premier utilisateur d'un domaine email crée son propre
    workspace (tenant + org), avec le rôle "admin" — identique au
    comportement de l'ancien /signup.
    """
    _ensure_supabase_column()

    supabase_user_id = payload["sub"]
    email = (payload.get("email") or "").strip().lower()
    metadata = payload.get("user_metadata") or {}
    display_name = (
        metadata.get("full_name")
        or metadata.get("name")
        or (email.split("@", 1)[0] if email else "User")
    )

    existing = _user_by_supabase_id(supabase_user_id)
    if existing:
        return existing

    if not email:
        raise SupabaseAuthError("token Supabase sans email exploitable")

    user_id = str(uuid.uuid4())
    org_id = str(uuid.uuid4())
    tenant_id = str(uuid.uuid4())
    tenant_name = f"{display_name}'s Workspace"

    ph = "%s" if is_postgres() else "?"

    if is_postgres():
        conn = get_pg_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO tenants (tenant_id, name, created_at) "
                "VALUES (%s, %s, CURRENT_TIMESTAMP)",
                (tenant_id, tenant_name),
            )
            cur.execute(
                "INSERT INTO orgs (org_id, tenant_id, name, created_at) "
                "VALUES (%s, %s, %s, CURRENT_TIMESTAMP)",
                (org_id, tenant_id, tenant_name),
            )
            cur.execute(
                """
                INSERT INTO users
                    (user_id, org_id, tenant_id, email, display_name,
                     role, active, supabase_user_id, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                """,
                (user_id, org_id, tenant_id, email, display_name,
                 "admin", True, supabase_user_id),
            )
            conn.commit()
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(_get_db_path())
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO tenants (tenant_id, name, created_at) "
                "VALUES (?, ?, CURRENT_TIMESTAMP)",
                (tenant_id, tenant_name),
            )
            cur.execute(
                "INSERT INTO orgs (org_id, tenant_id, name, created_at) "
                "VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                (org_id, tenant_id, tenant_name),
            )
            cur.execute(
                """
                INSERT INTO users
                    (user_id, org_id, tenant_id, email, display_name,
                     role, active, supabase_user_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (user_id, org_id, tenant_id, email, display_name,
                 "admin", 1, supabase_user_id),
            )
            conn.commit()
        finally:
            conn.close()

    logger.info(
        "supabase_user_provisioned",
        user_id=user_id,
        org_id=org_id,
        provider=(payload.get("app_metadata") or {}).get("provider", "email"),
    )

    return (user_id, org_id, tenant_id, email, display_name, "admin", True) 
