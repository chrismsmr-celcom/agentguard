"""
Policy Engine — Évalue les requêtes contre les policies.
"""
from typing import Dict, Any, Optional, List
import time

from .models import Policy, PolicyDecision, Decision, FailureMode
from .loader import PolicyLoader


class PolicyEngine:
    """
    Moteur d'évaluation de policies.
    
    Ordre d'évaluation (du plus restrictif au moins) :
    1. Explicit DENY (deny lists)
    2. Mandatory policies (capabilities)
    3. Rules (par priorité)
    4. Budget check
    5. Default: ALLOW
    """
    
    def __init__(
        self,
        policies_dir: Optional[str] = None,
        loader: Optional[PolicyLoader] = None,
    ):
        self.loader = loader or PolicyLoader(policies_dir)
        if policies_dir:
            count = self.loader.load_from_directory(policies_dir)
            print(f"📜 Loaded {count} policies from {policies_dir}")
    
    def load_policy(self, filepath: str) -> Optional[Policy]:
        """Charge une policy depuis un fichier."""
        return self.loader.load_from_file(filepath)
    
    def load_policy_string(self, yaml_content: str) -> Optional[Policy]:
        """Charge une policy depuis une string YAML."""
        return self.loader.load_from_string(yaml_content)
    
    def evaluate_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Évalue un appel d'outil contre la policy de l'agent.
        
        Args:
            agent_id: Identifiant de l'agent
            tool_name: Nom de l'outil appelé
            params: Paramètres de l'appel
            context: Contexte additionnel (user, session, data classification...)
        
        Returns:
            PolicyDecision avec action et raison
        """
        context = context or {}
        
        # 1. Trouve la policy applicable
        policy = self.loader.get_policy_for_agent(agent_id)
        if not policy:
            policy = self.loader.get_default_policy()
        
        if not policy:
            # Pas de policy → fail_closed par défaut
            return PolicyDecision(
                action=Decision.DENY,
                reason=f"No policy found for agent '{agent_id}' (fail_closed)",
                policy_name="none",
            )
        
        # 2. Vérifie la capability tool
        if not policy.capabilities.tools.is_allowed(tool_name):
            return PolicyDecision(
                action=Decision.DENY,
                reason=f"Tool '{tool_name}' not allowed by policy '{policy.name}'",
                policy_name=policy.name,
                policy_version=policy.version,
            )
        
        # 3. Vérifie filesystem si applicable
        fs_check = self._check_filesystem(policy, tool_name, params)
        if fs_check:
            return fs_check
        
        # 4. Vérifie network si applicable
        net_check = self._check_network(policy, tool_name, params)
        if net_check:
            return net_check
        
        # 5. Évalue les règles (par priorité)
        rule_decision = self._evaluate_rules(policy, tool_name, params, context)
        if rule_decision:
            return rule_decision
        
        # 6. Budget (si fourni dans context)
        budget_check = self._check_budget(policy, context)
        if budget_check:
            return budget_check
        
        # 7. Default: ALLOW
        return PolicyDecision(
            action=Decision.ALLOW,
            reason=f"Allowed by policy '{policy.name}'",
            policy_name=policy.name,
            policy_version=policy.version,
        )
    
    def _check_filesystem(
        self, policy: Policy, tool_name: str, params: Dict[str, Any]
    ) -> Optional[PolicyDecision]:
        """Vérifie les capacités filesystem."""
        # Détecte les outils qui accèdent au filesystem
        if tool_name in ("read_file", "read"):
            path = params.get("path") or params.get("file") or ""
            if path and not policy.capabilities.filesystem.can_read(path):
                return PolicyDecision(
                    action=Decision.DENY,
                    reason=f"Read access to '{path}' denied by policy",
                    policy_name=policy.name,
                )
        
        elif tool_name in ("write_file", "write", "append_file"):
            path = params.get("path") or params.get("file") or ""
            if path and not policy.capabilities.filesystem.can_write(path):
                return PolicyDecision(
                    action=Decision.DENY,
                    reason=f"Write access to '{path}' denied by policy",
                    policy_name=policy.name,
                )
        
        return None
    
    def _check_network(
        self, policy: Policy, tool_name: str, params: Dict[str, Any]
    ) -> Optional[PolicyDecision]:
        """Vérifie les capacités réseau."""
        # Détecte les outils qui font des requêtes réseau
        network_tools = ("http_request", "fetch", "curl", "wget", "send_email")
        if tool_name not in network_tools:
            return None
        
        destination = (
            params.get("url") or
            params.get("host") or
            params.get("domain") or
            params.get("to") or ""
        )
        
        if destination and not policy.capabilities.network.is_allowed(destination):
            return PolicyDecision(
                action=Decision.DENY,
                reason=f"Network access to '{destination}' denied by policy (SSRF protection)",
                policy_name=policy.name,
            )
        
        return None
    
    def _evaluate_rules(
        self,
        policy: Policy,
        tool_name: str,
        params: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Optional[PolicyDecision]:
        """Évalue les règles dans l'ordre de priorité."""
        # Contexte complet pour l'évaluation
        eval_context = {
            "tool": tool_name,
            "params": params,
            **context,
        }
        
        for rule in policy.rules:
            if self._matches_rule(rule, eval_context):
                return PolicyDecision(
                    action=rule.decision,
                    reason=rule.reason or f"Matched rule '{rule.name}'",
                    policy_name=policy.name,
                    policy_version=policy.version,
                    matched_rules=[rule.name],
                )
        
        return None
    
    def _matches_rule(self, rule, context: Dict[str, Any]) -> bool:
        """Vérifie si une règle matche le contexte."""
        for field_path, expected_value in rule.when.items():
            actual_value = self._get_nested(context, field_path)
            if not self._compare(actual_value, expected_value):
                return False
        return True
    
    @staticmethod
    def _get_nested(data: Dict[str, Any], path: str) -> Any:
        """Accès à un champ imbriqué via dot notation."""
        keys = path.split(".")
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
        return current
    
    @staticmethod
    def _compare(actual: Any, expected: Any) -> bool:
        """Compare deux valeurs (supporte opérateurs simples)."""
        # Format "operator:value" ex: "> 10000"
        if isinstance(expected, str) and len(expected) > 2:
            op = expected[0]
            if op in (">", "<", "=", "!") and expected[1] == " ":
                try:
                    val = float(expected[2:])
                    if actual is None:
                        return False
                    actual_num = float(actual)
                    if op == ">": return actual_num > val
                    if op == "<": return actual_num < val
                    if op == "=": return actual_num == val
                    if op == "!": return actual_num != val
                except (ValueError, TypeError):
                    pass
        
        # Comparaison simple
        return actual == expected
    
    def _check_budget(
        self, policy: Policy, context: Dict[str, Any]
    ) -> Optional[PolicyDecision]:
        """Vérifie les limites budgétaires."""
        session_spent = context.get("session_spent", 0.0)
        daily_spent = context.get("daily_spent", 0.0)
        projected_cost = context.get("projected_cost", 0.0)
        
        if session_spent + projected_cost > policy.budget.max_per_session:
            return PolicyDecision(
                action=Decision.DENY,
                reason=f"Session budget exceeded: {session_spent + projected_cost:.4f} > {policy.budget.max_per_session}",
                policy_name=policy.name,
            )
        
        if daily_spent + projected_cost > policy.budget.max_per_day:
            return PolicyDecision(
                action=Decision.DENY,
                reason=f"Daily budget exceeded: {daily_spent + projected_cost:.4f} > {policy.budget.max_per_day}",
                policy_name=policy.name,
            )
        
        return None
    
    def list_policies(self):
        """Liste les policies chargées."""
        return self.loader.list_policies()
