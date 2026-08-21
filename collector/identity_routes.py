"""
Identity Engine — CRUD endpoints (Phase 2).

Endpoints:
  POST /api/identity/tenants         — Créer un tenant (admin)
  POST /api/identity/orgs            — Créer une org (admin)
  POST /api/identity/users           — Créer un user (admin)
  POST /api/identity/agents          — Créer un agent (admin/developer)
  DELETE /api/identity/agents/<id>   — Révoquer un agent
  GET  /api/identity/agents          — Lister agents de l'org
  GET  /api/identity/me              — Identité courante
"""
import secrets
import structlog
from collector.schemas import AgentCreateRequest, UserCreateRequest, OrgCreateRequest
from pydantic import ValidationError
from typing import Optional
from flask import Blueprint, request, jsonify, g
from collector.db import get_pg_conn, is_postgres, get_sqlite_conn
from collector.auth import require_auth, require_role, resolve_full_identity
from identity import (
    Role,
    IdentityType,  # ✅ AJOUT
    generate_agent_api_key,
    hash_key,
    short_id,
)
import sqlite3

logger = structlog.get_logger("agentguard.identity")

identity_bp = Blueprint("identity", __name__, url_prefix="/api/identity")


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def _get_conn():
    """Retourne une connexion DB selon le type."""
    if is_postgres():
        return get_pg_conn()
    return get_sqlite_conn()


def _validate_tenant_name(name: str) -> Optional[str]:
    if not name or len(name) < 2 or len(name) > 64:
        return "name must be between 2 and 64 characters"
    return None


def _validate_email(email: str) -> Optional[str]:
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        return "invalid email format"
    return None


def _audit_identity_event(
    event_type: str,
    resource_type: str,
    resource_id: str,
    action: str,
    details: dict,
):
    """Log un événement identity dans la table identity_events."""
    identity = resolve_full_identity()
    if not identity:
        return
    
    try:
        import json
        event_id = secrets.token_hex(16)
        
        if is_postgres():
            conn = get_pg_conn()
            cur = conn.cursor()
            try:
                cur.execute("""
                    INSERT INTO identity_events
                    (event_id, tenant_id, org_id, actor_user_id, actor_agent_id,
                     event_type, resource_type, resource_id, action, details, ip_address)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    event_id, identity.tenant_id, identity.org_id,
                    identity.subject_id if identity.identity_type.value == "user" else None,
                    identity.subject_id if identity.identity_type.value == "agent" else None,
                    event_type, resource_type, resource_id, action,
                    json.dumps(details),
                    request.remote_addr,
                ))
                conn.commit()
            finally:
                conn.close()
        else:
            conn = sqlite3.connect(get_sqlite_conn().execute("PRAGMA database_list").fetchone()[-1] if False else "/tmp/agentguard.db")
            # Simplified : use get_sqlite_conn
            conn = get_sqlite_conn()
            cur = conn.cursor()
            try:
                cur.execute("""
                    INSERT INTO identity_events
                    (event_id, tenant_id, org_id, actor_user_id, actor_agent_id,
                     event_type, resource_type, resource_id, action, details, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event_id, identity.tenant_id, identity.org_id,
                    identity.subject_id if identity.identity_type.value == "user" else None,
                    identity.subject_id if identity.identity_type.value == "agent" else None,
                    event_type, resource_type, resource_id, action,
                    json.dumps(details),
                    request.remote_addr,
                ))
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        logger.warning("identity_audit_failed", error=str(e))


# ═══════════════════════════════════════════════════════════════
# TENANTS
# ═══════════════════════════════════════════════════════════════

@identity_bp.route("/tenants", methods=["POST"])
@require_role("admin")
def create_tenant():
    """Crée un nouveau tenant (entreprise cliente)."""
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    
    err = _validate_tenant_name(name)
    if err:
        return jsonify({"error": err}), 400
    
    tenant_id = f"tenant_{short_id(length=12)}"
    
    conn = _get_conn()
    cur = conn.cursor()
    try:
        if is_postgres():
            cur.execute(
                "INSERT INTO tenants (tenant_id, name) VALUES (%s, %s)",
                (tenant_id, name),
            )
        else:
            cur.execute(
                "INSERT INTO tenants (tenant_id, name) VALUES (?, ?)",
                (tenant_id, name),
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("tenant_creation_failed", error=str(e))
        return jsonify({"error": "creation failed"}), 500
    finally:
        conn.close()
    
    _audit_identity_event(
        event_type="tenant.created",
        resource_type="tenant",
        resource_id=tenant_id,
        action="create",
        details={"name": name},
    )
    
    logger.info("tenant_created", tenant_id=tenant_id, name=name)
    return jsonify({"tenant_id": tenant_id, "name": name}), 201


# ═══════════════════════════════════════════════════════════════
# ORGS
# ═══════════════════════════════════════════════════════════════

@identity_bp.route("/orgs", methods=["POST"])
@require_role("admin")
def create_org():
    """Crée une nouvelle org dans le tenant courant."""
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    tenant_id = (data.get("tenant_id") or "").strip()
    
    err = _validate_tenant_name(name)
    if err:
        return jsonify({"error": err}), 400
    
    # ✅ BOLA FIX : Résoudre l'identité AVANT toute opération
    identity = resolve_full_identity()
    if not identity:
        return jsonify({"error": "identity required"}), 401
    
    # Si tenant_id non fourni, utiliser celui de l'acteur (scope-safe)
    if not tenant_id:
        tenant_id = identity.tenant_id
    
    # ✅ BOLA FIX : Vérification d'appartenance STRICTE
    from collector.auth import authorize_resource_access
    if not authorize_resource_access(tenant_id, target_org_id=None):
        return jsonify({
            "error": "access denied: cannot create org in this tenant",
            "your_tenant": identity.tenant_id,
            "target_tenant": tenant_id,
        }), 403
    
    conn = _get_conn()
    cur = conn.cursor()
    try:
        # Vérifie que le tenant existe ET est actif
        if is_postgres():
            cur.execute(
                "SELECT tenant_id FROM tenants WHERE tenant_id = %s AND active = TRUE",
                (tenant_id,),
            )
        else:
            cur.execute(
                "SELECT tenant_id FROM tenants WHERE tenant_id = ? AND active = 1",
                (tenant_id,),
            )
        if not cur.fetchone():
            return jsonify({"error": "tenant not found"}), 404
        
        org_id = f"org_{short_id(length=12)}"
        
        if is_postgres():
            cur.execute(
                "INSERT INTO orgs (org_id, tenant_id, name) VALUES (%s, %s, %s)",
                (org_id, tenant_id, name),
            )
        else:
            cur.execute(
                "INSERT INTO orgs (org_id, tenant_id, name) VALUES (?, ?, ?)",
                (org_id, tenant_id, name),
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("org_creation_failed", error=str(e))
        return jsonify({"error": "creation failed"}), 500
    finally:
        conn.close()
    
    _audit_identity_event(
        event_type="org.created",
        resource_type="org",
        resource_id=org_id,
        action="create",
        details={"name": name, "tenant_id": tenant_id, "actor_tenant": identity.tenant_id},
    )
    
    logger.info("org_created", org_id=org_id, tenant_id=tenant_id)
    return jsonify({"org_id": org_id, "tenant_id": tenant_id, "name": name}), 201


# ═══════════════════════════════════════════════════════════════
# USERS
# ═══════════════════════════════════════════════════════════════

@identity_bp.route("/users", methods=["POST"])
@require_role("admin")
def create_user():
    """Crée un utilisateur humain — avec vérification BOLA stricte."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    display_name = (data.get("display_name") or "").strip()
    role_str = (data.get("role") or "viewer").strip()
    org_id = (data.get("org_id") or "").strip()
    
    err = _validate_email(email)
    if err:
        return jsonify({"error": err}), 400
    
    try:
        role = Role(role_str)
    except ValueError:
        return jsonify({
            "error": "invalid role",
            "valid_roles": [r.value for r in Role],
        }), 400
    
    # ✅ BOLA FIX : Résoudre l'identité AVANT toute opération
    identity = resolve_full_identity()
    if not identity:
        return jsonify({"error": "identity required"}), 401
    
    # Si org_id non fourni, utiliser celui de l'acteur (scope-safe)
    if not org_id:
        org_id = identity.org_id
    
    if not org_id:
        return jsonify({"error": "org_id required"}), 400
    
    conn = _get_conn()
    cur = conn.cursor()
    try:
        # Récupère l'org cible AVEC son tenant_id
        if is_postgres():
            cur.execute(
                "SELECT tenant_id FROM orgs WHERE org_id = %s AND active = TRUE",
                (org_id,),
            )
        else:
            cur.execute(
                "SELECT tenant_id FROM orgs WHERE org_id = ? AND active = 1",
                (org_id,),
            )
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "org not found"}), 404
        target_tenant_id = row[0]
        
        # ✅ BOLA FIX : Vérification STRICTE d'appartenance
        from collector.auth import authorize_resource_access
        if not authorize_resource_access(target_tenant_id, target_org_id=org_id):
            return jsonify({
                "error": "access denied: cannot create user in this org",
                "your_tenant": identity.tenant_id,
                "your_org": identity.org_id,
                "target_tenant": target_tenant_id,
                "target_org": org_id,
            }), 403
        
        # Vérifie unicité email dans l'org
        if is_postgres():
            cur.execute(
                "SELECT 1 FROM users WHERE org_id = %s AND email = %s",
                (org_id, email),
            )
        else:
            cur.execute(
                "SELECT 1 FROM users WHERE org_id = ? AND email = ?",
                (org_id, email),
            )
        if cur.fetchone():
            return jsonify({"error": "email already exists in this org"}), 409
        
        user_id = f"user_{short_id(length=12)}"
        
        if is_postgres():
            cur.execute("""
                INSERT INTO users (user_id, org_id, tenant_id, email, role, display_name)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, org_id, target_tenant_id, email, role.value, display_name))
        else:
            cur.execute("""
                INSERT INTO users (user_id, org_id, tenant_id, email, role, display_name)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, org_id, target_tenant_id, email, role.value, display_name))
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("user_creation_failed", error=str(e))
        return jsonify({"error": "creation failed"}), 500
    finally:
        conn.close()
    
    _audit_identity_event(
        event_type="user.created",
        resource_type="user",
        resource_id=user_id,
        action="create",
        details={
            "email": email,
            "role": role.value,
            "org_id": org_id,
            "actor_tenant": identity.tenant_id,
            "actor_org": identity.org_id,
        },
    )
    
    logger.info("user_created", user_id=user_id, email=email, role=role.value)
    return jsonify({
        "user_id": user_id,
        "org_id": org_id,
        "email": email,
        "role": role.value,
        "display_name": display_name,
    }), 201

# ═══════════════════════════════════════════════════════════════
# AGENTS (CRUD)
# ═══════════════════════════════════════════════════════════════

@identity_bp.route("/agents", methods=["POST"])
@require_role("admin", "developer")
def create_agent():
    """Crée un agent IA — avec vérification BOLA stricte."""
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()
    max_budget = float(data.get("max_budget_per_day", 100.0))
    org_id = (data.get("org_id") or "").strip()
    
    if not name or len(name) < 2:
        return jsonify({"error": "name must be at least 2 characters"}), 400
    if max_budget < 0 or max_budget > 10000:
        return jsonify({"error": "max_budget_per_day must be between 0 and 10000"}), 400@identity_bp.route("/agents", methods=["POST"])
@require_role("admin", "developer")
def create_agent():
    """Crée un agent IA — validation Pydantic stricte + BOLA enforcement."""
    from collector.schemas import AgentCreateRequest
    from pydantic import ValidationError
    
    # ✅ Validation Pydantic stricte (rejette NaN, Infinity, out-of-range)
    try:
    req = AgentCreateRequest(**(request.get_json(silent=True) or {}))
except ValidationError as e:  # ✅ Pas ValidationEr
    return jsonify({
        "error": "validation failed",
        "details": [
            {"field": err["loc"][-1] if err["loc"] else "root", "message": err["msg"]}
            for err in e.errors()
        ]
    }), 400
    
    name = req.name
    description = req.description or ""
    max_budget = req.max_budget_per_day
    org_id = req.org_id or ""
    
    # ✅ BOLA FIX : Résoudre l'identité AVANT toute opération
    identity = resolve_full_identity()
    if not identity:
        return jsonify({"error": "identity required"}), 401
    
    # Si org_id non fourni, utiliser celui de l'acteur (scope-safe)
    if not org_id:
        org_id = identity.org_id
    
    if not org_id:
        return jsonify({"error": "org_id required"}), 400
    
    conn = _get_conn()
    cur = conn.cursor()
    try:
        # Récupère l'org cible AVEC son tenant_id
        if is_postgres():
            cur.execute(
                "SELECT tenant_id FROM orgs WHERE org_id = %s AND active = TRUE",
                (org_id,),
            )
        else:
            cur.execute(
                "SELECT tenant_id FROM orgs WHERE org_id = ? AND active = 1",
                (org_id,),
            )
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "org not found"}), 404
        target_tenant_id = row[0]
        
        # ✅ BOLA FIX : Vérification STRICTE d'appartenance
        from collector.auth import authorize_resource_access
        if not authorize_resource_access(target_tenant_id, target_org_id=org_id):
            return jsonify({
                "error": "access denied: cannot create agent in this org",
                "your_tenant": identity.tenant_id,
                "your_org": identity.org_id,
                "target_tenant": target_tenant_id,
                "target_org": org_id,
            }), 403
        
        agent_id = f"agent_{short_id(length=12)}"
        api_key = generate_agent_api_key(target_tenant_id, org_id, agent_id)
        key_hash = hash_key(api_key)
        key_prefix = "_".join(api_key.split("_")[:4])  # ag_{t}_{o}_{a}
        
        if is_postgres():
            cur.execute("""
                INSERT INTO agents
                (agent_id, org_id, tenant_id, name, description, key_hash, key_prefix, max_budget_per_day)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (agent_id, org_id, target_tenant_id, name, description, key_hash, key_prefix, max_budget))
        else:
            cur.execute("""
                INSERT INTO agents
                (agent_id, org_id, tenant_id, name, description, key_hash, key_prefix, max_budget_per_day)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (agent_id, org_id, target_tenant_id, name, description, key_hash, key_prefix, max_budget))
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("agent_creation_failed", error=str(e))
        return jsonify({"error": "creation failed"}), 500
    finally:
        conn.close()
    
    _audit_identity_event(
        event_type="agent.created",
        resource_type="agent",
        resource_id=agent_id,
        action="create",
        details={
            "name": name, "org_id": org_id,
            "actor_tenant": identity.tenant_id, "actor_org": identity.org_id,
            "max_budget": max_budget,
        },
    )
    
    logger.info("agent_created", agent_id=agent_id, org_id=org_id, name=name)
    return jsonify({
        "agent_id": agent_id,
        "org_id": org_id,
        "name": name,
        "api_key": api_key,
        "warning": "⚠️ This API key will NEVER be shown again. Store it securely now.",
    }), 201


@identity_bp.route("/agents", methods=["GET"])
@require_role("admin", "developer", "auditor")
def list_agents():
    """Liste les agents de l'org courante (isolation multi-tenant)."""
    identity = resolve_full_identity()
    if not identity:
        return jsonify({"error": "identity required"}), 401
    
    org_id = identity.org_id
    include_revoked = request.args.get("include_revoked", "false").lower() == "true"
    
    conn = _get_conn()
    cur = conn.cursor()
    try:
        if is_postgres():
            if include_revoked:
                cur.execute("""
                    SELECT agent_id, name, description, active, max_budget_per_day,
                           created_at, last_seen_at
                    FROM agents WHERE org_id = %s
                    ORDER BY created_at DESC
                """, (org_id,))
            else:
                cur.execute("""
                    SELECT agent_id, name, description, active, max_budget_per_day,
                           created_at, last_seen_at
                    FROM agents WHERE org_id = %s AND active = TRUE
                    ORDER BY created_at DESC
                """, (org_id,))
            rows = cur.fetchall()
            agents = [
                {
                    "agent_id": r[0], "name": r[1], "description": r[2],
                    "active": r[3], "max_budget_per_day": r[4],
                    "created_at": str(r[5]) if r[5] else None,
                    "last_seen_at": str(r[6]) if r[6] else None,
                }
                for r in rows
            ]
        else:
            if include_revoked:
                cur.execute("""
                    SELECT agent_id, name, description, active, max_budget_per_day,
                           created_at, last_seen_at
                    FROM agents WHERE org_id = ?
                    ORDER BY created_at DESC
                """, (org_id,))
            else:
                cur.execute("""
                    SELECT agent_id, name, description, active, max_budget_per_day,
                           created_at, last_seen_at
                    FROM agents WHERE org_id = ? AND active = 1
                    ORDER BY created_at DESC
                """, (org_id,))
            rows = cur.fetchall()
            agents = [
                {
                    "agent_id": r[0], "name": r[1], "description": r[2],
                    "active": bool(r[3]), "max_budget_per_day": r[4],
                    "created_at": str(r[5]) if r[5] else None,
                    "last_seen_at": str(r[6]) if r[6] else None,
                }
                for r in rows
            ]
    finally:
        conn.close()
    
    return jsonify({"agents": agents, "count": len(agents)})


@identity_bp.route("/agents/<agent_id>", methods=["DELETE"])
@require_role("admin", "developer")
def revoke_agent(agent_id: str):
    """Révoque un agent (désactive sa clé API)."""
    identity = resolve_full_identity()
    if not identity:
        return jsonify({"error": "identity required"}), 401
    
    # ✅ Admin SYSTEM (clé legacy) peut révoquer n'importe quel agent
    # (super-admin global, pas restreint à une org)
    is_system_admin = (identity.identity_type == IdentityType.SYSTEM)
    
    conn = _get_conn()
    cur = conn.cursor()
    try:
        if is_postgres():
            if is_system_admin:
                cur.execute(
                    "UPDATE agents SET active = FALSE WHERE agent_id = %s",
                    (agent_id,),
                )
            else:
                cur.execute(
                    "UPDATE agents SET active = FALSE WHERE agent_id = %s AND org_id = %s",
                    (agent_id, identity.org_id),
                )
        else:
            if is_system_admin:
                cur.execute(
                    "UPDATE agents SET active = 0 WHERE agent_id = ?",
                    (agent_id,),
                )
            else:
                cur.execute(
                    "UPDATE agents SET active = 0 WHERE agent_id = ? AND org_id = ?",
                    (agent_id, identity.org_id),
                )
        affected = cur.rowcount
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("agent_revocation_failed", error=str(e))
        return jsonify({"error": "revocation failed"}), 500
    finally:
        conn.close()
    
    if affected == 0:
        return jsonify({"error": "agent not found or access denied"}), 404
    
    _audit_identity_event(
        event_type="agent.revoked",
        resource_type="agent",
        resource_id=agent_id,
        action="revoke",
        details={"org_id": identity.org_id, "system_admin": is_system_admin},
    )
    
    logger.info("agent_revoked", agent_id=agent_id, org_id=identity.org_id)
    return jsonify({"agent_id": agent_id, "status": "revoked"})


# ═══════════════════════════════════════════════════════════════
# CURRENT IDENTITY
# ═══════════════════════════════════════════════════════════════

@identity_bp.route("/me", methods=["GET"])
def get_me():
    """Retourne l'identité courante (nécessite auth mais pas de rôle spécifique)."""
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    identity = resolve_full_identity()
    if not identity:
        # Fallback legacy
        return jsonify({
            "identity_type": "legacy",
            "org_id": g.org_id,
            "note": "Using legacy API key — consider migrating to structured agent keys",
        })
    
    return jsonify(identity.to_dict())
