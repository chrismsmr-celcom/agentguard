"""
AgentGuard Policy Models
Définition des structures de données pour le Policy Engine.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


# -----------------------------------------------------------------------------
# ENUMS
# -----------------------------------------------------------------------------
class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class FailureMode(str, Enum):
    FAIL_CLOSED = "fail_closed"  # Par défaut, plus sécurisé
    FAIL_OPEN = "fail_open"


# -----------------------------------------------------------------------------
# CAPABILITIES
# -----------------------------------------------------------------------------
class ToolCapabilities(BaseModel):
    """Capacités d'outils : whitelist + blacklist."""
    allow: List[str] = Field(default_factory=list)
    deny: List[str] = Field(default_factory=list)

    def is_allowed(self, tool_name: str) -> bool:
        """Vérifie si un outil est autorisé."""
        # DENY gagne toujours sur ALLOW (principe de sécurité)
        if self.deny:
            for pattern in self.deny:
                if self._matches(tool_name, pattern):
                    return False

        # Si une whitelist est définie, l'outil doit y être
        if self.allow:
            for pattern in self.allow:
                if self._matches(tool_name, pattern):
                    return True
            return False

        # Par défaut : autorisé si pas de whitelist
        return True

    @staticmethod
    def _matches(name: str, pattern: str) -> bool:
        """Match simple avec support de * (wildcard)."""
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            return name.startswith(pattern[:-1])
        return name == pattern


class FilesystemCapabilities(BaseModel):
    """Capacités filesystem : read/write/deny paths."""
    read: List[str] = Field(default_factory=list)
    write: List[str] = Field(default_factory=list)
    deny: List[str] = Field(default_factory=list)

    def can_read(self, path: str) -> bool:
        return self._check_access(path, self.read)

    def can_write(self, path: str) -> bool:
        return self._check_access(path, self.write)

    def _check_access(self, path: str, allowed: List[str]) -> bool:
        # DENY gagne toujours
        for pattern in self.deny:
            if self._matches_path(path, pattern):
                return False

        # Si liste définie, doit matcher
        if allowed:
            for pattern in allowed:
                if self._matches_path(path, pattern):
                    return True
            return False

        return True

    @staticmethod
    def _matches_path(path: str, pattern: str) -> bool:
        """Match de paths avec support de ** (recursive) et *."""
        import fnmatch
        import re

        # Normalise
        path = path.replace("\\", "/").rstrip("/")
        pattern = pattern.replace("\\", "/").rstrip("/")

        # ** = récursif
        if "**" in pattern:
            # Protège ** avant de transformer les * simples
            regex = pattern
            regex = regex.replace("**/", "\x00DOUBLESTARSLASH\x00")
            regex = regex.replace("**", "\x00DOUBLESTAR\x00")
            # Maintenant on peut transformer les * simples en [^/]*
            regex = regex.replace("*", "[^/]*")
            # Restaure les placeholders avec les vrais regex
            regex = regex.replace("\x00DOUBLESTARSLASH\x00", "(.*/)?")
            regex = regex.replace("\x00DOUBLESTAR\x00", ".*")
            return bool(re.match(f"^{regex}$", path))

        return fnmatch.fnmatch(path, pattern)


class NetworkCapabilities(BaseModel):
    """Capacités réseau : allowlist/denylist de destinations."""
    allow: List[str] = Field(default_factory=list)
    deny: List[str] = Field(default_factory=list)
    default: str = "deny"  # deny par défaut

    def is_allowed(self, destination: str) -> bool:
        # Blocages SSRF par défaut (toujours appliqués)
        ssrf_blocklist = [
            "127.0.0.1", "localhost", "0.0.0.0",
            "169.254.169.254",  # AWS metadata
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168.",
        ]
        for blocked in ssrf_blocklist:
            if destination.startswith(blocked) or blocked in destination:
                return False

        # DENY explicite
        for pattern in self.deny:
            if self._matches(destination, pattern):
                return False

        # Si whitelist définie
        if self.allow:
            for pattern in self.allow:
                if self._matches(destination, pattern):
                    return True
            return False

        return self.default == "allow"

    @staticmethod
    def _matches(dest: str, pattern: str) -> bool:
        """Match de domaines/IPs."""
        import fnmatch
        # Normalise (retire protocole)
        dest = dest.replace("https://", "").replace("http://", "").split("/")[0]
        pattern = pattern.replace("https://", "").replace("http://", "").split("/")[0]

        return fnmatch.fnmatch(dest, pattern) or dest == pattern


class Capabilities(BaseModel):
    """Ensemble des capacités d'un agent."""
    tools: ToolCapabilities = Field(default_factory=ToolCapabilities)
    filesystem: FilesystemCapabilities = Field(default_factory=FilesystemCapabilities)
    network: NetworkCapabilities = Field(default_factory=NetworkCapabilities)


# -----------------------------------------------------------------------------
# BUDGET
# -----------------------------------------------------------------------------
class BudgetLimits(BaseModel):
    """Limites budgétaires."""
    max_per_session: float = Field(10.0, ge=0)
    max_per_day: float = Field(100.0, ge=0)


# -----------------------------------------------------------------------------
# RULES
# -----------------------------------------------------------------------------
class RuleCondition(BaseModel):
    """Condition d'une règle (simple pour v1)."""
    field: str  # ex: "data.classification", "tool", "params.amount"
    operator: str = "eq"  # eq, neq, gt, lt, contains, in
    value: Any


class Rule(BaseModel):
    """Règle policy : condition → décision."""
    name: str
    when: Dict[str, Any]  # Format simple: {field: value}
    decision: Decision
    reason: str = ""
    priority: int = 100  # Plus bas = plus prioritaire


# -----------------------------------------------------------------------------
# POLICY
# -----------------------------------------------------------------------------
class Policy(BaseModel):
    """Policy complète pour un ou plusieurs agents."""
    version: int = 1
    name: str
    description: str = ""

    agents: List[str] = Field(default_factory=list)

    capabilities: Capabilities = Field(default_factory=Capabilities)
    rules: List[Rule] = Field(default_factory=list)
    budget: BudgetLimits = Field(default_factory=BudgetLimits)

    failure_mode: FailureMode = FailureMode.FAIL_CLOSED

    # Metadata
    created_at: Optional[str] = None
    created_by: Optional[str] = None

    def applies_to(self, agent_id: str) -> bool:
        """Vérifie si cette policy s'applique à un agent."""
        if not self.agents:
            return True  # Policy universelle
        return agent_id in self.agents


# -----------------------------------------------------------------------------
# DECISION (résultat d'évaluation)
# -----------------------------------------------------------------------------
@dataclass
class PolicyDecision:
    """Résultat d'une évaluation de policy."""
    action: Decision
    reason: str = ""
    policy_name: str = ""
    policy_version: int = 0
    matched_rules: List[str] = field(default_factory=list)
    risk_score: int = 0  # 0-100

    def is_allowed(self) -> bool:
        return self.action == Decision.ALLOW

    def is_denied(self) -> bool:
        return self.action == Decision.DENY

    def requires_approval(self) -> bool:
        return self.action == Decision.REQUIRE_APPROVAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "reason": self.reason,
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "matched_rules": self.matched_rules,
            "risk_score": self.risk_score,
        }
