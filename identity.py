"""
AgentGuard Identity Engine — Multi-tenant RBAC.

Hiérarchie :
  Tenant (entreprise) → Org (département) → {User, Agent} → Session

Rôles RBAC :
  - admin      : tout gérer
  - developer  : créer agents, voir traces
  - auditor    : read-only sur audit + traces
  - viewer     : dashboard uniquement

Format clé API agent :
  ag_{tenant_short}_{org_short}_{agent_short}_{random32}
  Ex: ag_acme_fin_prod_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
"""
import os
import re
import secrets
import hashlib
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any, List


class Role(str, Enum):
    ADMIN = "admin"
    DEVELOPER = "developer"
    AUDITOR = "auditor"
    VIEWER = "viewer"

    @classmethod
    def hierarchy(cls) -> Dict["Role", int]:
        """Plus le niveau est élevé, plus le rôle a de permissions."""
        return {
            cls.ADMIN: 100,
            cls.DEVELOPER: 70,
            cls.AUDITOR: 40,
            cls.VIEWER: 10,
        }

    def has_permission(self, required: "Role") -> bool:
        """Vérifie si self a au moins le niveau de required."""
        h = self.hierarchy()
        return h.get(self, 0) >= h.get(required, 0)


class IdentityType(str, Enum):
    USER = "user"
    AGENT = "agent"
    SYSTEM = "system"


@dataclass
class Tenant:
    """Entreprise cliente (top-level isolation)."""
    tenant_id: str
    name: str
    created_at: float = field(default_factory=time.time)
    active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Org:
    """Département/projet au sein d'un tenant."""
    org_id: str
    tenant_id: str
    name: str
    created_at: float = field(default_factory=time.time)
    active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class User:
    """Utilisateur humain (se connecte au dashboard)."""
    user_id: str
    org_id: str
    tenant_id: str
    email: str
    role: Role
    display_name: str = ""
    created_at: float = field(default_factory=time.time)
    active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["role"] = self.role.value
        return d


@dataclass
class Agent:
    """Agent IA (bot) avec sa propre clé API."""
    agent_id: str
    org_id: str
    tenant_id: str
    name: str
    description: str = ""
    created_at: float = field(default_factory=time.time)
    active: bool = True
    max_budget_per_day: float = 100.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ResolvedIdentity:
    """
    Identité résolue à partir d'une clé API.
    Injectée dans g.identity par le middleware auth.
    """
    identity_type: IdentityType
    tenant_id: str
    org_id: str
    subject_id: str  # user_id ou agent_id
    role: Role
    agent_name: Optional[str] = None
    user_email: Optional[str] = None

    def is_admin(self) -> bool:
        return self.role == Role.ADMIN

    def has_role(self, required: Role) -> bool:
        return self.role.has_permission(required)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["identity_type"] = self.identity_type.value
        d["role"] = self.role.value
        return d


# ═══════════════════════════════════════════════════════════════
# KEY GENERATION & PARSING
# ═══════════════════════════════════════════════════════════════

# Format : ag_{tenant}_{org}_{agent}_{random32}
_AGENT_KEY_PATTERN = re.compile(
    r"^ag_([a-z0-9]{3,8})_([a-z0-9]{3,8})_([a-z0-9]{3,8})_([a-z0-9]{32})$"
)


def short_id(prefix: str = "", length: int = 6) -> str:
    """Génère un ID court lowercase alphanumérique."""
    rand = secrets.token_hex(length)[:length]
    return f"{prefix}{rand}" if prefix else rand


def generate_agent_api_key(tenant_id: str, org_id: str, agent_id: str) -> str:
    """
    Génère une clé API agent au format structuré.
    Permet d'identifier rapidement l'agent sans lookup DB (préfixe).
    """
    # Extraction des short IDs (on prend les 6 derniers chars)
    t_short = tenant_id.replace("tenant_", "")[-6:].lower()
    o_short = org_id.replace("org_", "")[-6:].lower()
    a_short = agent_id.replace("agent_", "")[-6:].lower()
    random_part = secrets.token_hex(16)  # 32 chars hex
    return f"ag_{t_short}_{o_short}_{a_short}_{random_part}"


def parse_agent_api_key(key: str) -> Optional[Dict[str, str]]:
    """
    Parse une clé API agent.
    Retourne None si format invalide (ex: ancienne clé "ag-xxx").
    """
    if not key or not key.startswith("ag_"):
        return None
    m = _AGENT_KEY_PATTERN.match(key)
    if not m:
        return None
    return {
        "tenant_short": m.group(1),
        "org_short": m.group(2),
        "agent_short": m.group(3),
        "random_part": m.group(4),
    }


def hash_key(key: str) -> str:
    """Hash SHA256 pour stockage DB (ne jamais stocker la clé en clair)."""
    return hashlib.sha256(key.encode()).hexdigest()


# ═══════════════════════════════════════════════════════════════
# PERMISSIONS MATRIX
# ═══════════════════════════════════════════════════════════════

# Permissions par rôle (ce que chaque rôle peut faire)
PERMISSIONS = {
    Role.ADMIN: {
        "org:create", "org:delete",
        "user:create", "user:delete", "user:assign_role",
        "agent:create", "agent:delete", "agent:revoke",
        "traces:view_all", "audit:view", "audit:verify",
        "settings:edit", "billing:view",
    },
    Role.DEVELOPER: {
        "agent:create", "agent:revoke",  # ses propres agents
        "traces:view_own_org", "audit:view",
        "dashboard:view",
    },
    Role.AUDITOR: {
        "traces:view_own_org", "audit:view", "audit:verify",
        "dashboard:view",
    },
    Role.VIEWER: {
        "dashboard:view",
    },
}


def role_has_permission(role: Role, permission: str) -> bool:
    """Vérifie si un rôle a une permission spécifique."""
    return permission in PERMISSIONS.get(role, set())
