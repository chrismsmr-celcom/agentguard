"""
Policy Loader — Charge et valide les policies depuis YAML.

Responsabilités :
- Charger des policies depuis un fichier YAML ou un dossier.
- Valider leur structure via les modèles Pydantic.
- Indexer les policies par nom et par agent.
- Supporter .yaml et .yml.
- Éviter les doublons lors des recherches.
- Permettre de distinguer clairement une policy dédiée à un agent
  d'une policy universelle.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

import structlog
import yaml

from .models import (
    BudgetLimits,
    Capabilities,
    Decision,
    FailureMode,
    FilesystemCapabilities,
    NetworkCapabilities,
    Policy,
    Rule,
    ToolCapabilities,
)

logger = structlog.get_logger("agentguard.policy.loader")


class PolicyLoader:
    """Charge, valide et indexe les policies AgentGuard depuis YAML."""

    def __init__(self, policies_dir: Optional[str] = None):
        self.policies_dir = Path(policies_dir) if policies_dir else None

        # Index principal : policy.name -> Policy
        self._policies: Dict[str, Policy] = {}

        # Index agent : agent_id -> Policy
        self._agent_policies: Dict[str, Policy] = {}

        # Policies universelles : policies avec agents=[]
        self._universal_policies: List[Policy] = []

    # ------------------------------------------------------------------
    # DIRECTORY LOADING
    # ------------------------------------------------------------------

    def load_from_directory(self, directory: Optional[str] = None) -> int:
        """
        Charge toutes les policies YAML d'un dossier.

        Supporte :
        - *.yaml
        - *.yml

        Returns:
            Nombre de policies correctement chargées.
        """
        dir_path = Path(directory) if directory else self.policies_dir

        if not dir_path:
            logger.warning(
                "policy_directory_not_configured",
                directory=str(directory) if directory else None,
            )
            return 0

        if not dir_path.exists():
            logger.warning(
                "policy_directory_not_found",
                directory=str(dir_path),
            )
            return 0

        if not dir_path.is_dir():
            logger.error(
                "policy_path_not_directory",
                path=str(dir_path),
            )
            return 0

        files = sorted(
            {
                *dir_path.glob("*.yaml"),
                *dir_path.glob("*.yml"),
            }
        )

        if not files:
            logger.warning(
                "policy_directory_empty",
                directory=str(dir_path),
            )
            return 0

        count = 0

        for yaml_file in files:
            policy = self.load_from_file(str(yaml_file))

            if policy is not None:
                count += 1

        logger.info(
            "policies_loaded_from_directory",
            directory=str(dir_path),
            files=len(files),
            loaded=count,
            total=len(self._policies),
        )

        return count

    # ------------------------------------------------------------------
    # FILE LOADING
    # ------------------------------------------------------------------

    def load_from_file(self, filepath: str) -> Optional[Policy]:
        """Charge et valide une policy depuis un fichier YAML."""

        path = Path(filepath)

        if not path.exists():
            logger.error(
                "policy_file_not_found",
                filepath=str(path),
            )
            return None

        if not path.is_file():
            logger.error(
                "policy_path_not_file",
                filepath=str(path),
            )
            return None

        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            policy = self._parse_policy(data, str(path))

            if policy is None:
                return None

            self._register_policy(policy)

            logger.info(
                "policy_loaded",
                name=policy.name,
                agents=policy.agents,
                source=str(path),
                version=policy.version,
            )

            return policy

        except yaml.YAMLError as exc:
            logger.error(
                "policy_yaml_parse_failed",
                filepath=str(path),
                error=str(exc),
            )
            return None

        except Exception as exc:
            logger.error(
                "policy_load_failed",
                filepath=str(path),
                error=str(exc),
            )
            return None

    # ------------------------------------------------------------------
    # STRING LOADING
    # ------------------------------------------------------------------

    def load_from_string(
        self,
        yaml_content: str,
        name: str = "inline",
    ) -> Optional[Policy]:
        """Charge et valide une policy depuis une string YAML."""

        if not isinstance(yaml_content, str) or not yaml_content.strip():
            logger.error(
                "inline_policy_empty",
                source=name,
            )
            return None

        try:
            data = yaml.safe_load(yaml_content)

            policy = self._parse_policy(data, name)

            if policy is None:
                return None

            self._register_policy(policy)

            logger.info(
                "inline_policy_loaded",
                name=policy.name,
                agents=policy.agents,
                source=name,
                version=policy.version,
            )

            return policy

        except yaml.YAMLError as exc:
            logger.error(
                "inline_policy_yaml_parse_failed",
                source=name,
                error=str(exc),
            )
            return None

        except Exception as exc:
            logger.error(
                "inline_policy_load_failed",
                source=name,
                error=str(exc),
            )
            return None

    # ------------------------------------------------------------------
    # PARSING
    # ------------------------------------------------------------------

    def _parse_policy(
        self,
        data: object,
        source: str,
    ) -> Optional[Policy]:
        """
        Parse un dictionnaire YAML en Policy validée.

        La validation finale est assurée par les modèles de policy.
        """

        if not isinstance(data, dict):
            raise ValueError(
                f"Policy in {source} must be a mapping, "
                f"got {type(data).__name__}"
            )

        # --------------------------------------------------------------
        # NAME
        # --------------------------------------------------------------

        name = data.get("name")

        if not isinstance(name, str) or not name.strip():
            raise ValueError(
                f"Policy in {source} missing valid 'name' field"
            )

        name = name.strip()

        # --------------------------------------------------------------
        # DESCRIPTION
        # --------------------------------------------------------------

        description = data.get("description", "")

        if description is None:
            description = ""

        if not isinstance(description, str):
            description = str(description)

        # --------------------------------------------------------------
        # VERSION
        # --------------------------------------------------------------

        version = data.get("version", 1)

        try:
            version = int(version)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Policy '{name}' has invalid version: {version!r}"
            ) from exc

        # --------------------------------------------------------------
        # AGENTS
        # --------------------------------------------------------------

        agents = data.get("agents", [])

        if agents is None:
            agents = []

        if not isinstance(agents, list):
            raise ValueError(
                f"Policy '{name}' field 'agents' must be a list"
            )

        normalized_agents: List[str] = []

        for agent in agents:
            if not isinstance(agent, str):
                raise ValueError(
                    f"Policy '{name}' contains non-string agent ID: "
                    f"{agent!r}"
                )

            agent = agent.strip()

            if agent and agent not in normalized_agents:
                normalized_agents.append(agent)

        # --------------------------------------------------------------
        # CAPABILITIES
        # --------------------------------------------------------------

        caps_data = data.get("capabilities", {})

        if caps_data is None:
            caps_data = {}

        if not isinstance(caps_data, dict):
            raise ValueError(
                f"Policy '{name}' field 'capabilities' must be a mapping"
            )

        tools_data = caps_data.get("tools", {})
        filesystem_data = caps_data.get("filesystem", {})
        network_data = caps_data.get("network", {})

        if tools_data is None:
            tools_data = {}

        if filesystem_data is None:
            filesystem_data = {}

        if network_data is None:
            network_data = {}

        if not isinstance(tools_data, dict):
            raise ValueError(
                f"Policy '{name}' capabilities.tools must be a mapping"
            )

        if not isinstance(filesystem_data, dict):
            raise ValueError(
                f"Policy '{name}' capabilities.filesystem must be a mapping"
            )

        if not isinstance(network_data, dict):
            raise ValueError(
                f"Policy '{name}' capabilities.network must be a mapping"
            )

        tools = ToolCapabilities(**tools_data)
        filesystem = FilesystemCapabilities(**filesystem_data)
        network = NetworkCapabilities(**network_data)

        capabilities = Capabilities(
            tools=tools,
            filesystem=filesystem,
            network=network,
        )

        # --------------------------------------------------------------
        # RULES
        # --------------------------------------------------------------

        rules_data = data.get("rules", [])

        if rules_data is None:
            rules_data = []

        if not isinstance(rules_data, list):
            raise ValueError(
                f"Policy '{name}' field 'rules' must be a list"
            )

        rules: List[Rule] = []

        for index, rule_data in enumerate(rules_data):
            if not isinstance(rule_data, dict):
                raise ValueError(
                    f"Policy '{name}' rule #{index + 1} must be a mapping"
                )

            rule_name = rule_data.get("name", "unnamed")

            if not isinstance(rule_name, str):
                rule_name = str(rule_name)

            when = rule_data.get("when", {})

            if when is None:
                when = {}

            if not isinstance(when, dict):
                raise ValueError(
                    f"Policy '{name}' rule '{rule_name}' "
                    f"field 'when' must be a mapping"
                )

            decision_raw = rule_data.get("decision", "ALLOW")

            if isinstance(decision_raw, Decision):
                decision = decision_raw
            else:
                decision_str = str(decision_raw).strip().upper()

                try:
                    decision = Decision(decision_str)
                except ValueError:
                    raise ValueError(
                        f"Policy '{name}' rule '{rule_name}' "
                        f"has invalid decision: {decision_raw!r}"
                    )

            reason = rule_data.get("reason", "")

            if reason is None:
                reason = ""

            if not isinstance(reason, str):
                reason = str(reason)

            priority_raw = rule_data.get("priority", 100)

            try:
                priority = int(priority_raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Policy '{name}' rule '{rule_name}' "
                    f"has invalid priority: {priority_raw!r}"
                ) from exc

            rules.append(
                Rule(
                    name=rule_name.strip() or "unnamed",
                    when=when,
                    decision=decision,
                    reason=reason,
                    priority=priority,
                )
            )

        # Lowest priority number is evaluated first.
        rules.sort(key=lambda rule: rule.priority)

        # --------------------------------------------------------------
        # BUDGET
        # --------------------------------------------------------------

        budget_data = data.get("budget", {})

        if budget_data is None:
            budget_data = {}

        if not isinstance(budget_data, dict):
            raise ValueError(
                f"Policy '{name}' field 'budget' must be a mapping"
            )

        budget = BudgetLimits(**budget_data)

        # --------------------------------------------------------------
        # FAILURE MODE
        # --------------------------------------------------------------

        failure_mode_raw = data.get(
            "failure_mode",
            FailureMode.FAIL_CLOSED.value,
        )

        if isinstance(failure_mode_raw, FailureMode):
            failure_mode = failure_mode_raw
        else:
            failure_mode_str = str(failure_mode_raw).strip().lower()

            try:
                failure_mode = FailureMode(failure_mode_str)
            except ValueError:
                raise ValueError(
                    f"Policy '{name}' has invalid failure_mode: "
                    f"{failure_mode_raw!r}"
                )

        # --------------------------------------------------------------
        # FINAL MODEL VALIDATION
        # --------------------------------------------------------------

        return Policy(
            version=version,
            name=name,
            description=description,
            agents=normalized_agents,
            capabilities=capabilities,
            rules=rules,
            budget=budget,
            failure_mode=failure_mode,
        )

    # ------------------------------------------------------------------
    # REGISTRATION / INDEXING
    # ------------------------------------------------------------------

    def _register_policy(self, policy: Policy) -> None:
        """
        Enregistre une policy dans les index.

        Une policy agent-specific prend priorité sur une policy
        universelle pour l'agent concerné.
        """

        # Remplace une éventuelle version précédente de la même policy.
        self._policies[policy.name] = policy

        # Une policy sans agents est universelle.
        if not policy.agents:
            # Évite les doublons si la même policy est rechargée.
            self._universal_policies = [
                existing
                for existing in self._universal_policies
                if existing.name != policy.name
            ]

            self._universal_policies.append(policy)

        else:
            # Si la policy était précédemment universelle et vient
            # d'être rechargée avec des agents explicites, on la retire.
            self._universal_policies = [
                existing
                for existing in self._universal_policies
                if existing.name != policy.name
            ]

        # Index agent-specific.
        for agent_id in policy.agents:
            existing = self._agent_policies.get(agent_id)

            if existing is not None and existing.name != policy.name:
                logger.warning(
                    "agent_policy_replaced",
                    agent_id=agent_id,
                    previous_policy=existing.name,
                    new_policy=policy.name,
                )

            self._agent_policies[agent_id] = policy

    # ------------------------------------------------------------------
    # POLICY LOOKUP
    # ------------------------------------------------------------------

    def get_policy_for_agent(
        self,
        agent_id: str,
    ) -> Optional[Policy]:
        """
        Retourne la policy applicable à un agent.

        Ordre de priorité :
        1. Policy explicitement associée à l'agent.
        2. Policy universelle.
        3. None.

        IMPORTANT :
        Cette méthode ne crée jamais de fallback implicite.
        L'absence de policy retourne explicitement None.
        """

        if not agent_id:
            return None

        agent_id = str(agent_id).strip()

        if not agent_id:
            return None

        # 1. Policy dédiée.
        dedicated = self._agent_policies.get(agent_id)

        if dedicated is not None:
            return dedicated

        # 2. Policy universelle.
        for policy in self._universal_policies:
            if policy.applies_to(agent_id):
                return policy
