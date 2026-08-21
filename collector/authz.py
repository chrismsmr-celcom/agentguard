"""
Authorization Kernel — single source of truth for all authorization decisions.

Architecture:
    ┌─────────────────────────────────┐
    │       Authorization Kernel      │
    │  authorize(actor, action,       │
    │            resource, context)   │
    └────────────┬────────────────────┘
                 │
    ┌────────────┼──────────────┐
    ▼            ▼              ▼
Identity      Policy       Resource
(actor)     (action)      (scope)

Usage:
    from collector.authz import authorize, Action
    
    if not authorize(actor=identity, action=Action.AGENT_CREATE, resource=target_org):
        return jsonify({"error": "forbidden"}), 403
"""
from enum import Enum
from typing import Optional, Any
import structlog

logger = structlog.get_logger("agentguard.authz")


class Action(str, Enum):
    """All authorized actions in the system."""
    # Tenant-level
    TENANT_CREATE = "tenant:create"
    TENANT_DELETE = "tenant:delete"
    TENANT_READ = "tenant:read"
    
    # Org-level
    ORG_CREATE = "org:create"
    ORG_DELETE = "org:delete"
    ORG_READ = "org:read"
    
    # User-level
    USER_CREATE = "user:create"
    USER_DELETE = "user:delete"
    USER_ASSIGN_ROLE = "user:assign_role"
    USER_READ = "user:read"
    
    # Agent-level
    AGENT_CREATE = "agent:create"
    AGENT_DELETE = "agent:delete"
    AGENT_REVOKE = "agent:revoke"
    AGENT_LIST = "agent:list"
    AGENT_READ = "agent:read"
    
    # Data-level
    TRACES_READ = "traces:read"
    TRACES_WRITE = "traces:write"
    METRICS_READ = "metrics:read"
    AUDIT_READ = "audit:read"
    
    # Settings
    SETTINGS_EDIT = "settings:edit"
    BILLING_VIEW = "billing:view"
    
    # API keys
    APIKEY_CREATE = "apikey:create"
    APIKEY_REVOKE = "apikey:revoke"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


# ═══════════════════════════════════════════════════════════════
# PERMISSION MATRIX
# ═══════════════════════════════════════════════════════════════

def _get_role_permissions():
    """Lazy import to avoid circular dependencies."""
    try:
        from identity import Role
    except ImportError:
        return {}
    
    return {
        Role.ADMIN: {
            # Tenant admin can do everything in their tenant
            Action.TENANT_READ,
            Action.ORG_CREATE, Action.ORG_DELETE, Action.ORG_READ,
            Action.USER_CREATE, Action.USER_DELETE, Action.USER_ASSIGN_ROLE, Action.USER_READ,
            Action.AGENT_CREATE, Action.AGENT_DELETE, Action.AGENT_REVOKE, Action.AGENT_LIST, Action.AGENT_READ,
            Action.TRACES_READ, Action.TRACES_WRITE, Action.METRICS_READ, Action.AUDIT_READ,
            Action.SETTINGS_EDIT, Action.BILLING_VIEW,
            Action.APIKEY_CREATE, Action.APIKEY_REVOKE,
        },
        Role.DEVELOPER: {
            # Developer can manage agents, read traces, in their org
            Action.ORG_READ,
            Action.USER_READ,
            Action.AGENT_CREATE, Action.AGENT_REVOKE, Action.AGENT_LIST, Action.AGENT_READ,
            Action.TRACES_READ, Action.TRACES_WRITE, Action.METRICS_READ,
        },
        Role.AUDITOR: {
            # Auditor is read-only with audit access
            Action.ORG_READ,
            Action.USER_READ,
            Action.AGENT_LIST, Action.AGENT_READ,
            Action.TRACES_READ, Action.METRICS_READ, Action.AUDIT_READ,
        },
        Role.VIEWER: {
            # Viewer has minimal read access
            Action.ORG_READ,
            Action.AGENT_LIST, Action.AGENT_READ,
            Action.METRICS_READ,
        },
    }


# ═══════════════════════════════════════════════════════════════
# CORE AUTHORIZATION FUNCTION
# ═══════════════════════════════════════════════════════════════

def authorize(
    actor,
    action: Action,
    resource: Optional[Any] = None,
    context: Optional[dict] = None,
) -> bool:
    """
    Authorization Kernel — single entry point for ALL authorization decisions.
    
    Args:
        actor: ResolvedIdentity object (or None)
        action: Action enum value
        resource: str (tenant_id or org_id), dict {"tenant_id": ..., "org_id": ...},
                  or object with .tenant_id / .org_id attributes
        context: Optional dict with extra info for logging
    
    Returns:
        True if ALLOW, False if DENY
    
    Rules (in priority order):
        1. No actor → DENY
        2. SYSTEM identity → ALLOW (with warning log, to be deprecated)
        3. Cross-tenant mismatch → DENY (always, for any role)
        4. Role doesn't have permission for action → DENY
        5. Cross-org mismatch (non-admin) → DENY
        6. Otherwise → ALLOW
    """
    try:
        from identity import IdentityType, Role
    except ImportError:
        logger.error("authz_identity_module_missing")
        return False
    
    context = context or {}
    
    # ─────────────────────────────────────────────────────
    # RULE 1: No actor → DENY
    # ─────────────────────────────────────────────────────
    if actor is None:
        logger.warning(
            "authz_denied",
            reason="no_actor",
            action=action.value,
            resource=_describe_resource(resource),
            **context,
        )
        return False
    
    # ─────────────────────────────────────────────────────
    # RULE 2: SYSTEM identity (legacy) → ALLOW with warning
    # ─────────────────────────────────────────────────────
    if actor.identity_type == IdentityType.SYSTEM:
        logger.warning(
            "authz_system_access",
            action=action.value,
            resource=_describe_resource(resource),
            note="SYSTEM has global access — migrate to scoped identities",
            **context,
        )
        return True
    
    # ─────────────────────────────────────────────────────
    # Extract target tenant/org from resource
    # ─────────────────────────────────────────────────────
    target_tenant = _extract_tenant(resource)
    target_org = _extract_org(resource)
    
    # ─────────────────────────────────────────────────────
    # RULE 3: Cross-tenant → ALWAYS DENY
    # ─────────────────────────────────────────────────────
    if target_tenant and actor.tenant_id != target_tenant:
        logger.warning(
            "authz_denied",
            reason="cross_tenant",
            action=action.value,
            actor_tenant=actor.tenant_id,
            target_tenant=target_tenant,
            actor_role=_role_value(actor.role),
            **context,
        )
        return False
    
    # ─────────────────────────────────────────────────────
    # RULE 4: Role permission check
    # ─────────────────────────────────────────────────────
    permissions = _get_role_permissions()
    allowed_actions = permissions.get(actor.role, set())
    
    if action not in allowed_actions:
        logger.warning(
            "authz_denied",
            reason="insufficient_role",
            action=action.value,
            actor_role=_role_value(actor.role),
            allowed=[a.value for a in allowed_actions][:5],  # first 5 for log brevity
            **context,
        )
        return False
    
    # ─────────────────────────────────────────────────────
    # RULE 5: Cross-org check (role-based)
    # ─────────────────────────────────────────────────────
    if target_org:
        # Admin can access any org in their tenant
        if actor.role == Role.ADMIN:
            # Already passed tenant check above, so OK
            pass
        else:
            # Developer/Auditor/Viewer restricted to their own org
            if actor.org_id != target_org:
                logger.warning(
                    "authz_denied",
                    reason="cross_org",
                    action=action.value,
                    actor_org=actor.org_id,
                    target_org=target_org,
                    actor_role=_role_value(actor.role),
                    **context,
                )
                return False
    
    # ─────────────────────────────────────────────────────
    # RULE 6: ALLOW
    # ─────────────────────────────────────────────────────
    logger.debug(
        "authz_allowed",
        action=action.value,
        actor_role=_role_value(actor.role),
        actor_tenant=actor.tenant_id,
        resource=_describe_resource(resource),
    )
    return True


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def _extract_tenant(resource) -> Optional[str]:
    """Extract tenant_id from various resource shapes."""
    if resource is None:
        return None
    if isinstance(resource, str):
        if resource.startswith("tenant_"):
            return resource
        return None
    if hasattr(resource, "tenant_id"):
        return resource.tenant_id
    if isinstance(resource, dict):
        return resource.get("tenant_id")
    return None


def _extract_org(resource) -> Optional[str]:
    """Extract org_id from various resource shapes."""
    if resource is None:
        return None
    if isinstance(resource, str):
        if resource.startswith("org_"):
            return resource
        return None
    if hasattr(resource, "org_id"):
        return resource.org_id
    if isinstance(resource, dict):
        return resource.get("org_id")
    return None


def _describe_resource(resource) -> str:
    """Safe resource description for logs (no sensitive data)."""
    if resource is None:
        return "<none>"
    if isinstance(resource, str):
        return resource
    tenant = _extract_tenant(resource)
    org = _extract_org(resource)
    parts = []
    if tenant:
        parts.append(f"tenant:{tenant}")
    if org:
        parts.append(f"org:{org}")
    return " / ".join(parts) if parts else str(resource)[:50]


def _role_value(role) -> str:
    """Safe role value extraction."""
    if hasattr(role, "value"):
        return role.value
    return str(role)
