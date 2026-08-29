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

Identity types supported:
    - User/Agent (ResolvedIdentity)      → role-based, tenant-scoped
    - Platform Service (g.platform_identity) → permission-based, explicit
    - SYSTEM (legacy, deprecated)        → global allow (with toggle)

Usage:
    from collector.authz import authorize, Action
    
    if not authorize(actor=identity, action=Action.AGENT_CREATE, resource=target_org):
        return jsonify({"error": "forbidden"}), 403
"""
import os
from enum import Enum
from typing import Optional, Any
import structlog
from flask import g

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
# PLATFORM IDENTITY PERMISSION MAPPING
# Maps Action (authorization kernel) → PlatformPermission (scoped identities)
# ═══════════════════════════════════════════════════════════════

def _get_action_to_platform_permission():
    """Lazy import + cached mapping."""
    try:
        from collector.platform_identity import PlatformPermission
    except ImportError:
        return {}
    
    return {
        # Tenant operations
        Action.TENANT_CREATE: PlatformPermission.TENANT_CREATE,
        Action.TENANT_DELETE: PlatformPermission.TENANT_DELETE,
        Action.TENANT_READ: PlatformPermission.TENANT_READ,
        
        # Org operations
        Action.ORG_CREATE: PlatformPermission.ORG_CREATE,
        Action.ORG_DELETE: PlatformPermission.ORG_DELETE,
        Action.ORG_READ: PlatformPermission.ORG_READ,
        
        # User/Agent management
        Action.USER_CREATE: PlatformPermission.USER_MANAGE,
        Action.USER_DELETE: PlatformPermission.USER_MANAGE,
        Action.USER_ASSIGN_ROLE: PlatformPermission.USER_MANAGE,
        Action.USER_READ: PlatformPermission.ORG_READ,
        Action.AGENT_CREATE: PlatformPermission.AGENT_MANAGE,
        Action.AGENT_DELETE: PlatformPermission.AGENT_MANAGE,
        Action.AGENT_REVOKE: PlatformPermission.AGENT_MANAGE,
        Action.AGENT_LIST: PlatformPermission.AGENT_MANAGE,
        Action.AGENT_READ: PlatformPermission.AGENT_MANAGE,
        
        # Observability
        Action.TRACES_READ: PlatformPermission.TRACES_READ,
        Action.TRACES_WRITE: None,  # Write not granted to platform identities
        Action.METRICS_READ: PlatformPermission.METRICS_READ,
        Action.AUDIT_READ: PlatformPermission.AUDIT_READ,
        
        # Billing
        Action.BILLING_VIEW: PlatformPermission.BILLING_READ,
        
        # Settings / API keys — not granted to scoped platform identities
        Action.SETTINGS_EDIT: PlatformPermission.PLATFORM_CONFIG,
        Action.APIKEY_CREATE: PlatformPermission.PLATFORM_CONFIG,
        Action.APIKEY_REVOKE: PlatformPermission.PLATFORM_CONFIG,
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
        1. No actor AND no platform identity → DENY
        2. Platform identity (agp_...) → permission-based check
        3. SYSTEM identity (legacy) → ALLOW with warning (toggle to disable)
        4. Cross-tenant mismatch → DENY (always)
        5. Role doesn't have permission → DENY
        6. Cross-org mismatch (non-admin) → DENY
        7. Otherwise → ALLOW
    """
    try:
        from identity import IdentityType, Role
    except ImportError:
        logger.error("authz_identity_module_missing")
        return False
    
    context = context or {}
    
    # ─────────────────────────────────────────────────────
    # RULE 0: Check for platform identity first (g.platform_identity)
    # Platform identities act INDEPENDENTLY of actor — they represent
    # service-to-service auth (audit-service, billing-service, etc.)
    # ─────────────────────────────────────────────────────
    platform_identity = getattr(g, "platform_identity", None)
    if platform_identity:
        return _authorize_platform(
            platform_identity=platform_identity,
            action=action,
            resource=resource,
            context=context,
        )
    
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
    # RULE 2: SYSTEM identity (LEGACY, DEPRECATED)
    # Two modes:
    #   - Default: ALLOW with high-visibility warning (migration phase)
    #   - AGENTGUARD_DISABLE_LEGACY_SYSTEM=true: DENY (Phase 3, 6 months+)
    # ─────────────────────────────────────────────────────
    if actor.identity_type == IdentityType.SYSTEM:
        disable_system = os.environ.get(
            "AGENTGUARD_DISABLE_LEGACY_SYSTEM", "false"
        ).lower() == "true"
        
        if disable_system:
            # ── PHASE 3: Hard block ──
            logger.error(
                "authz_system_blocked",
                action=action.value,
                resource=_describe_resource(resource),
                note="SYSTEM identity disabled via AGENTGUARD_DISABLE_LEGACY_SYSTEM. "
                     "Migrate to platform service identities (agp_...).",
                migration_docs="https://docs.agentguard.io/migration/platform-identities",
                **context,
            )
            return False
        
        # ── PHASE 1/2: Soft warning ──
        logger.warning(
            "authz_system_access_deprecated",
            action=action.value,
            resource=_describe_resource(resource),
            note="DEPRECATED: SYSTEM has global access. Migrate to scoped "
                 "platform identities (agp_...). Will be blocked in 6 months.",
            migration_docs="https://docs.agentguard.io/migration/platform-identities",
            blast_radius="global",
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
            allowed=[a.value for a in allowed_actions][:5],
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
# PLATFORM IDENTITY AUTHORIZATION (NEW)
# ═══════════════════════════════════════════════════════════════

def _authorize_platform(
    platform_identity: dict,
    action: Action,
    resource: Optional[Any],
    context: dict,
) -> bool:
    """
    Authorize a platform identity (agp_... key).
    
    Platform identities use EXPLICIT permissions instead of role matrices.
    No tenant/org scope — they are cross-tenant by design but with
    granular action restrictions.
    """
    try:
        from collector.platform_identity import PlatformPermission
    except ImportError:
        logger.error("authz_platform_module_missing")
        return False
    
    service_name = platform_identity.get("service_name", "unknown")
    granted_permissions = platform_identity.get("permissions", set())
    
    # Map action to required platform permission
    action_map = _get_action_to_platform_permission()
    required_permission = action_map.get(action)
    
    # Action not mapped → DENY (fail closed)
    if required_permission is None:
        logger.warning(
            "authz_platform_denied",
            reason="action_not_mapped",
            service=service_name,
            action=action.value,
            resource=_describe_resource(resource),
            note="This action is not available to platform identities",
            **context,
        )
        return False
    
    # Permission not granted → DENY
    if required_permission not in granted_permissions:
        logger.warning(
            "authz_platform_denied",
            reason="insufficient_permission",
            service=service_name,
            action=action.value,
            required=required_permission.value,
            granted=[p.value for p in granted_permissions],
            resource=_describe_resource(resource),
            **context,
        )
        return False
    
    # ALLOW — log with service context
    logger.info(
        "authz_platform_allowed",
        service=service_name,
        action=action.value,
        permission=required_permission.value,
        resource=_describe_resource(resource),
        **context,
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
