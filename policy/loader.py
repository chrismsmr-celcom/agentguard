"""
Policy Loader — Charge et valide les policies depuis YAML.
"""
import os
from pathlib import Path
from typing import Dict, List, Optional
import yaml

from .models import Policy, FailureMode


class PolicyLoader:
    """Charge les policies depuis un dossier ou des fichiers YAML."""
    
    def __init__(self, policies_dir: Optional[str] = None):
        self.policies_dir = Path(policies_dir) if policies_dir else None
        self._policies: Dict[str, Policy] = {}
    
    def load_from_directory(self, directory: Optional[str] = None) -> int:
        """Charge toutes les policies d'un dossier.
        
        Returns:
            Nombre de policies chargées
        """
        dir_path = Path(directory) if directory else self.policies_dir
        if not dir_path or not dir_path.exists():
            return 0
        
        count = 0
        for yaml_file in dir_path.glob("*.yaml"):
            try:
                policy = self.load_from_file(str(yaml_file))
                if policy:
                    count += 1
            except Exception as e:
                print(f"⚠️ Failed to load {yaml_file}: {e}")
        
        return count
    
    def load_from_file(self, filepath: str) -> Optional[Policy]:
        """Charge une policy depuis un fichier YAML."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            
            policy = self._parse_policy(data, filepath)
            if policy:
                # Index par nom
                self._policies[policy.name] = policy
                # Index par agent
                for agent in policy.agents:
                    self._policies[f"agent:{agent}"] = policy
            
            return policy
        except Exception as e:
            print(f"❌ Error loading {filepath}: {e}")
            return None
    
    def load_from_string(self, yaml_content: str, name: str = "inline") -> Optional[Policy]:
        """Charge une policy depuis une string YAML."""
        try:
            data = yaml.safe_load(yaml_content)
            policy = self._parse_policy(data, name)
            if policy:
                self._policies[policy.name] = policy
                for agent in policy.agents:
                    self._policies[f"agent:{agent}"] = policy
            return policy
        except Exception as e:
            print(f"❌ Error parsing inline policy: {e}")
            return None
    
    def _parse_policy(self, data: dict, source: str) -> Optional[Policy]:
        """Parse un dict en Policy (avec validation)."""
        if not isinstance(data, dict):
            raise ValueError(f"Policy must be a dict, got {type(data)}")
        
        # Champs requis
        name = data.get("name")
        if not name:
            raise ValueError(f"Policy in {source} missing 'name' field")
        
        # Parse capabilities
        from .models import (
            Capabilities, ToolCapabilities,
            FilesystemCapabilities, NetworkCapabilities,
            BudgetLimits, Rule, Decision
        )
        
        caps_data = data.get("capabilities", {})
        tools = ToolCapabilities(**caps_data.get("tools", {}))
        filesystem = FilesystemCapabilities(**caps_data.get("filesystem", {}))
        network = NetworkCapabilities(**caps_data.get("network", {}))
        capabilities = Capabilities(tools=tools, filesystem=filesystem, network=network)
        
        # Parse rules
        rules = []
        for rule_data in data.get("rules", []):
            decision_str = rule_data.get("decision", "ALLOW").upper()
            try:
                decision = Decision(decision_str)
            except ValueError:
                decision = Decision.ALLOW
            
            rule = Rule(
                name=rule_data.get("name", "unnamed"),
                when=rule_data.get("when", {}),
                decision=decision,
                reason=rule_data.get("reason", ""),
                priority=rule_data.get("priority", 100),
            )
            rules.append(rule)
        
        # Parse budget
        budget_data = data.get("budget", {})
        budget = BudgetLimits(**budget_data)
        
        # Parse failure mode
        failure_mode_str = data.get("failure_mode", "fail_closed")
        try:
            failure_mode = FailureMode(failure_mode_str)
        except ValueError:
            failure_mode = FailureMode.FAIL_CLOSED
        
        return Policy(
            version=data.get("version", 1),
            name=name,
            description=data.get("description", ""),
            agents=data.get("agents", []),
            capabilities=capabilities,
            rules=sorted(rules, key=lambda r: r.priority),
            budget=budget,
            failure_mode=failure_mode,
        )
    
    def get_policy_for_agent(self, agent_id: str) -> Optional[Policy]:
        """Récupère la policy d'un agent spécifique."""
        # D'abord cherche une policy dédiée
        agent_key = f"agent:{agent_id}"
        if agent_key in self._policies:
            return self._policies[agent_key]
        
        # Sinon cherche une policy qui s'applique
        for policy in self._policies.values():
            if policy.applies_to(agent_id):
                return policy
        
        return None
    
    def get_default_policy(self) -> Optional[Policy]:
        """Récupère la policy par défaut."""
        return self._policies.get("default")
    
    def list_policies(self) -> List[Policy]:
        """Liste toutes les policies uniques."""
        seen = set()
        policies = []
        for policy in self._policies.values():
            if policy.name not in seen:
                seen.add(policy.name)
                policies.append(policy)
        return policies
