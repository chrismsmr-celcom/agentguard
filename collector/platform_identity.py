"""
Platform-scoped identities — replaces global SYSTEM trust.

Each service identity has EXPLICIT permissions. No more "SYSTEM = ALLOW all".

Service identities:
- platform-admin: full platform control (replacement for legacy SYSTEM)
- audit-service: read-only audit logs and traces
- billing-service: metrics and cost queries
- migration-service: cross-tenant data operations

Key format: agp_{service}_{random_32_chars}
    Example: agp_audit_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
"""
import hashlib
import hmac
import os
import secrets
import structlog
from enum import Enum
from typing import Optional, Set

logger = structlog.get_logger("agentguard.platform")


# ═══════════════════════════════════════════════════════════════
# PLATFORM IDENTITY TYPES
# ═══════════════════════════════════════════════════════════════

class PlatformService(str, Enum):
    """Platform service identities."""
    ADMIN = "admin"           # Full platform control
    AUDIT = "audit"           # Read-only audit/traces
    BILLING = "billing"       # Metrics + billing
    MIGRATION = "migration"   # Cross-tenant data ops


class PlatformPermission(str, Enum):
    """Granular permissions for platform services."""
    # Tenant management
    TENANT_CREATE = "tenant:create"
    TENANT_DELETE = "tenant:delete"
    TENANT_READ = "tenant:read"
    TENANT_LIST = "tenant:list"
    
    # Org management (cross-tenant)
    ORG_CREATE = "org:create"
    ORG_DELETE = "org:delete"
    ORG_READ = "org:read"
    
    # User/Agent management (cross-tenant)
    USER_MANAGE = "user:manage"
    AGENT_MANAGE = "agent:manage"
    
    # Observability
    AUDIT_READ = "audit:read"
    TRACES_READ = "traces:read"
    METRICS_READ = "metrics:read"
    
    # Billing
    BILLING_READ = "billing:read"
    BILLING_MANAGE = "billing:manage"
    
    # Platform operations
    MIGRATION_EXECUTE = "migration:execute"
    PLATFORM_CONFIG = "platform:config"


# ═══════════════════════════════════════════════════════════════
# PERMISSION MATRICES — least privilege by default
# ═══════════════════════════════════════════════════════════════

PLATFORM_PERMISSIONS: dict = {
    PlatformService.ADMIN: {
        # Full platform control (replacement for legacy SYSTEM)
        PlatformPermission.TENANT_CREATE,
        PlatformPermission.TENANT_DELETE,
        PlatformPermission.TENANT_READ,
        PlatformPermission.TENANT_LIST,
        PlatformPermission.ORG_CREATE,
        PlatformPermission.ORG_DELETE,
        PlatformPermission.ORG_READ,
        PlatformPermission.USER_MANAGE,
        PlatformPermission.AGENT_MANAGE,
        PlatformPermission.AUDIT_READ,
        PlatformPermission.TRACES_READ,
        PlatformPermission.METRICS_READ,
        PlatformPermission.BILLING_READ,
        PlatformPermission.BILLING_MANAGE,
        PlatformPermission.MIGRATION_EXECUTE,
        PlatformPermission.PLATFORM_CONFIG,
    },
    PlatformService.AUDIT: {
        # Read-only observability
        PlatformPermission.TENANT_LIST,
        PlatformPermission.TENANT_READ,
        PlatformPermission.ORG_READ,
        PlatformPermission.AUDIT_READ,
        PlatformPermission.TRACES_READ,
    },
    PlatformService.BILLING: {
        # Metrics + cost only
        PlatformPermission.TENANT_LIST,
        PlatformPermission.TENANT_READ,
        PlatformPermission.ORG_READ,
        PlatformPermission.METRICS_READ,
        PlatformPermission.BILLING_READ,
    },
    PlatformService.MIGRATION: {
        # Cross-tenant data ops (use sparingly)
        PlatformPermission.TENANT_READ,
        PlatformPermission.TENANT_LIST,
        PlatformPermission.ORG_READ,
        PlatformPermission.MIGRATION_EXECUTE,
    },
}


def service_has_permission(service: PlatformService, permission: PlatformPermission) -> bool:
    """Check if a platform service has a specific permission."""
    perms = PLATFORM_PERMISSIONS.get(service, set())
    return permission in perms


# ═══════════════════════════════════════════════════════════════
# PLATFORM API KEY MANAGEMENT
# ═══════════════════════════════════════════════════════════════

PLATFORM_KEY_PREFIX = "agp_"


def generate_platform_key(service: PlatformService) -> str:
    """Generate a new platform API key.
    
    Format: agp_{service}_{random_32}
    Example: agp_audit_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
    
    Returns the FULL key (show once — store hash only).
    """
    random_part = secrets.token_urlsafe(32)[:32]
    return f"{PLATFORM_KEY_PREFIX}{service.value}_{random_part}"


def hash_platform_key(key: str) -> str:
    """Hash a platform key with SHA-256 for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


def parse_platform_key(key: str) -> Optional[dict]:
    """Parse a platform API key.
    
    Returns: {"service": PlatformService, "key_hash": str} or None
    """
    if not key or not key.startswith(PLATFORM_KEY_PREFIX):
        return None
    
    parts = key.split("_")
    # agp_{service}_{random} → 3 parts
    if len(parts) < 3 or parts[0] != "agp":
        return None
    
    service_str = parts[1]
    try:
        service = PlatformService(service_str)
    except ValueError:
        return None
    
    return {
        "service": service,
        "key_hash": hash_platform_key(key),
        "service_name": service.value,
    }


# ═══════════════════════════════════════════════════════════════
# ENVIRONMENT-BASED PLATFORM KEYS
# ═══════════════════════════════════════════════════════════════

def get_platform_key_for_service(service: PlatformService) -> Optional[str]:
    """Get platform key for a service from environment.
    
    Environment variable: AGENTGUARD_PLATFORM_KEY_{SERVICE}
    Example: AGENTGUARD_PLATFORM_KEY_AUDIT=agp_audit_xxx...
    """
    env_var = f"AGENTGUARD_PLATFORM_KEY_{service.value.upper()}"
    key = os.environ.get(env_var)
    if not key:
        return None
    
    # Validate format
    parsed = parse_platform_key(key)
    if not parsed or parsed["service"] != service:
        logger.warning(
            "platform_key_invalid_format",
            service=service.value,
            env_var=env_var,
        )
        return None
    
    return key


def resolve_platform_identity(api_key: str) -> Optional[dict]:
    """Resolve a platform API key to its identity.
    
    Returns: {
        "service": PlatformService,
        "permissions": Set[PlatformPermission],
        "identity_type": "platform",
    } or None
    """
    parsed = parse_platform_key(api_key)
    if not parsed:
        return None
    
    service = parsed["service"]
    
    # Verify against environment variable (or DB in future)
    expected_key = get_platform_key_for_service(service)
    if not expected_key:
        logger.debug("platform_key_not_configured", service=service.value)
        return None
    
    # Constant-time comparison
    if not hmac.compare_digest(api_key.encode(), expected_key.encode()):
        logger.warning("platform_key_mismatch", service=service.value)
        return None
    
    permissions = PLATFORM_PERMISSIONS.get(service, set())
    
    return {
        "service": service,
        "service_name": service.value,
        "permissions": permissions,
        "identity_type": "platform",
    }


# ═══════════════════════════════════════════════════════════════
# HELPERS FOR ROUTES
# ═══════════════════════════════════════════════════════════════

def require_platform_permission(*required_permissions: PlatformPermission):
    """Decorator to require specific platform permissions.
    
    Usage:
        @app.route("/api/platform/tenants")
        @require_platform_permission(PlatformPermission.TENANT_LIST)
        def list_tenants():
            ...
    """
    def decorator(f):
        from functools import wraps
        from flask import request, jsonify, g
        
        @wraps(f)
        def wrapper(*args, **kwargs):
            platform_identity = getattr(g, "platform_identity", None)
            
            if not platform_identity:
                return jsonify({
                    "error": "Platform authentication required",
                    "hint": "Use agp_... API key with appropriate service role",
                }), 401
            
            missing = [
                p.value for p in required_permissions
                if p not in platform_identity["permissions"]
            ]
            
            if missing:
                logger.warning(
                    "platform_permission_denied",
                    service=platform_identity.get("service_name"),
                    required=[p.value for p in required_permissions],
                    missing=missing,
                )
                return jsonify({
                    "error": "Insufficient platform permissions",
                    "required": [p.value for p in required_permissions],
                    "missing": missing,
                    "service": platform_identity.get("service_name"),
                }), 403
            
            return f(*args, **kwargs)
        
        return wrapper
    return decorator
