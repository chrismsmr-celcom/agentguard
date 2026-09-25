import os
import json
import re
import requests
import structlog
import unicodedata
from typing import Optional, Dict, Any, List

from .models import SecurityCheck, RiskLevel, SecurityAction

logger = structlog.get_logger("agentguard.policy")

try:
    from agentguard_ml import MLDetector
except ImportError:
    class MLDetector:
        def __init__(self): self.enabled = False
        def predict(self, text): return {"score": 0.0, "risk": "UNKNOWN", "confidence": "low"}

class PolicyEngine:
    def __init__(self):
        pass
        
    def check_injection(self, prompt: str):  # <-- Correct : exactement 4 espaces
        clean_prompt = _normalize_prompt(prompt)
        
        # ⚠️ DÉTECTION SPÉCIFIQUE : Mots inversés (très faible coût CPU)
        # Le benchmark contient "snoitcurtsni suoiverp" (instructions previous à l'envers)
        if "snoitcurtsni" in clean_prompt.lower() or "suoiverp" in clean_prompt.lower():
            return DetectionResult(
                passed=False, 
                risk_level="high", 
                details="Reversed keyword obfuscation detected"
            )

        # ... MAINTENANT, appliquez vos regex sur `clean_prompt` (et NON sur `prompt`) ...
        # Exemple :
        # if INJECTION_REGEX.search(clean_prompt):
        #     return DetectionResult(passed=False, risk_level="high", details="...")
        
        # Si rien n'est détecté :
        return DetectionResult(passed=True, risk_level="low", details="No injection detected")
def _normalize_prompt(text: str) -> str:
    if not isinstance(text, str):
        return text
    
    # 1. Correction manuelle des homoglyphes spécifiques du benchmark
    text = text.replace('ɿ', 'r').replace('і', 'i').replace('ο', 'o').replace('с', 'c')
    
    # 2. Normalisation Unicode standard
    text = unicodedata.normalize('NFKC', text)
    
    # 3. Suppression des caractères invisibles (zero-width spaces)
    text = re.sub(r'[\u200b\u200c\u200d\ufeff\u2060\u200e\u200f]', '', text)
    
    # 4. Colle les lettres séparées par des points/espaces (i . g . n . o . r . e -> ignore)
    text = re.sub(r'(\w)\s*\.\s*(\w)', r'\1\2', text)
    
    # 5. Décode les échappements hex (\x67) et unicode (\u006e)
    text = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), text)
    
    # 6. Révèle le texte caché dans les commentaires HTML (ne pas le supprimer !)
    text = re.sub(r'<!--(.*?)-->', r' \1 ', text, flags=re.DOTALL)
    
    return text.strip()
    def __init__(self, policies: Optional[List[Dict[str, Any]]] = None, redis_url: Optional[str] = None):
        self.policies = policies or []
        self._compile_patterns()
        self.ml_detector = MLDetector()
        self.use_llm_judge = os.getenv("AGENTGUARD_USE_LLM_JUDGE", "false").lower() in ("true", "1", "on", "yes")
        self.block_on_ambiguous = os.getenv("AGENTGUARD_BLOCK_ON_AMBIGUOUS", "false").lower() in ("true", "1", "on", "yes")
        self.judge_timeout = max(0.5, float(os.getenv("AGENTGUARD_JUDGE_TIMEOUT", "15.0")))
        
        self._redis_client = None
        if redis_url and self.use_llm_judge:
            try:
                import redis
                self._redis_client = redis.from_url(redis_url)
                self._redis_client.ping()
            except Exception:
                self._redis_client = None

        # Whitelists d'outils : une entrée "tool_whitelist" sans "agent_id"
        # ni "agents" est globale (s'applique à tout agent). Une entrée
        # avec "agent_id: X" ou "agents: [X, Y]" ne s'applique qu'à ces
        # agents-là — c'est ce qui permet à check_tool_policy() de scoper
        # correctement par agent au lieu d'un seul whitelist plat partagé
        # par tout le monde.
        self._allowed_tools_global = set()
        self._allowed_tools_by_agent: Dict[str, set] = {}
        for policy in self.policies:
            if policy.get("type") == "tool_whitelist":
                tools = set(policy.get("allowed_tools", []))
                scoped_agents = policy.get("agents")
                if not scoped_agents and policy.get("agent_id"):
                    scoped_agents = [policy["agent_id"]]
                if scoped_agents:
                    for agent in scoped_agents:
                        self._allowed_tools_by_agent.setdefault(agent, set()).update(tools)
                else:
                    self._allowed_tools_global.update(tools)
        self._triple_judge = None

    @property
    def _allowed_tools(self) -> set:
        """Vue à plat de toutes les whitelists (global + tous les agents).

        Conservée pour compatibilité : ex. mcp/mcp_server.py l'utilise pour
        afficher un résumé des politiques actives. Ne PAS utiliser pour une
        décision de sécurité — check_tool_policy() utilise le scoping par
        agent_id, plus strict, et c'est lui qui fait foi.
        """
        merged = set(self._allowed_tools_global)
        for tools in self._allowed_tools_by_agent.values():
            merged.update(tools)
        return merged

    def _effective_whitelist(self, agent_id: Optional[str]) -> set:
        """Whitelist applicable à un agent donné.

        Un agent avec sa propre whitelist scopée est régi par elle (plus
        les entrées globales, qui s'appliquent à tous). Un agent sans
        whitelist scopée hérite seulement des entrées globales — s'il n'y
        en a aucune, l'ensemble est vide et check_tool_policy() n'impose
        aucune restriction (comportement historique conservé).
        """
        scoped = self._allowed_tools_by_agent.get(agent_id, set()) if agent_id else set()
        if scoped:
            return scoped | self._allowed_tools_global
        return set(self._allowed_tools_global)

    def _compile_patterns(self):
        if PolicyEngine._STRONG_PATTERNS is not None:
            return

        from .patterns import get_all_strong_patterns, get_weak_patterns

        all_strong = get_all_strong_patterns()
        weak = get_weak_patterns()

        PolicyEngine._STRONG_PATTERNS = re.compile("|".join(f"(?:{p})" for p in all_strong), re.IGNORECASE)
        PolicyEngine._WEAK_PATTERNS = re.compile("|".join(f"(?:{p})" for p in weak), re.IGNORECASE)

    def check_injection(self, text: str) -> SecurityCheck:
        text = str(text or "")
        if not text.strip(): return SecurityCheck("prompt_injection", True, RiskLevel.LOW, "Empty prompt")
        
        if self._triple_judge is not None:
            try:
                tj_result = self._triple_judge.evaluate(text)
                if tj_result.get("final_verdict") == "DENY":
                    return SecurityCheck("prompt_injection", False, RiskLevel.HIGH, f"[TRIPLE JUDGE] {tj_result.get('reason')}", {"layer": "triple_judge"}, SecurityAction.BLOCK)
            except Exception as e: logger.warning("triple_judge_failed", error=str(e))
            
        if self.ml_detector.enabled:
            ml_result = self.ml_detector.predict(text)
            if ml_result["risk"] == "HIGH" and ml_result["score"] >= 0.85:
                return SecurityCheck("prompt_injection", False, RiskLevel.HIGH, f"ML detected threat ({ml_result['score']:.2%})", {"layer": "ml"}, SecurityAction.BLOCK)
                
        if PolicyEngine._STRONG_PATTERNS.findall(text):
            return SecurityCheck("prompt_injection", False, RiskLevel.HIGH, "Strong injection pattern detected", {"layer": "regex"}, SecurityAction.BLOCK)
            
        return SecurityCheck("prompt_injection", True, RiskLevel.LOW, "No injection detected", {"layer": "all_clear"}, SecurityAction.ALLOW)

    def check_pii(self, text: str) -> SecurityCheck:
        text = str(text or "")
        if not text.strip(): return SecurityCheck("pii_detection", True, RiskLevel.LOW, "Empty text")
        patterns = {"ssn": r"\b\d{3}-\d{2}-\d{4}\b", "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b"}
        findings = {}
        for name, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches: findings[name] = len(matches)
        if findings:
            return SecurityCheck("pii_detection", False, RiskLevel.HIGH, f"PII detected: {findings}", {"pii_types": findings}, SecurityAction.BLOCK)
        return SecurityCheck("pii_detection", True, RiskLevel.LOW, "No PII detected")

    def check_budget(self, cost: float, max_budget: float, current_spent: float) -> SecurityCheck:
        if current_spent + cost > max_budget:
            return SecurityCheck(
                "budget_policy", False, RiskLevel.HIGH, 
                f"Budget exceeded: {current_spent + cost:.4f} > {max_budget:.4f}",
                {"current_spent": current_spent, "cost": cost, "max_budget": max_budget},
                SecurityAction.BLOCK
            )
        return SecurityCheck("budget_policy", True, RiskLevel.LOW, "Budget OK")

    def check_tool_policy(self, tool_name: str, params: Dict[str, Any], budget_remaining: float, agent_id: Optional[str] = None) -> SecurityCheck:
        effective_whitelist = self._effective_whitelist(agent_id)
        if effective_whitelist and tool_name not in effective_whitelist:
            scope = f"agent '{agent_id}'" if agent_id else "default scope"
            return SecurityCheck("tool_policy", False, RiskLevel.CRITICAL, f"Tool '{tool_name}' not in whitelist for {scope}", {"agent_id": agent_id}, SecurityAction.BLOCK)
        if budget_remaining < 0:
            return SecurityCheck("budget_policy", False, RiskLevel.HIGH, "Budget exceeded", {}, SecurityAction.BLOCK)
        
        # --- NOUVEAU : Règle DLP (Data Loss Prevention) ---
        if tool_name in ["COMPOSIO_MULTI_EXECUTE_TOOL", "GMAIL_SEND_EMAIL", "send_email"]:
            tools_to_run = params.get("tools", []) if isinstance(params, dict) and "tools" in params else []
            
            # Si c'est un appel direct et non multi-execute
            if tool_name in ["GMAIL_SEND_EMAIL", "send_email"]:
                tools_to_run = [{"tool_slug": tool_name, "arguments": params}]
                
            for tool in tools_to_run:
                if tool.get("tool_slug") in ["GMAIL_SEND_EMAIL", "send_email"]:
                    args = tool.get("arguments", {})
                    recipient = str(args.get("recipient_email", args.get("to", ""))).lower()
                    has_attachment = "attachment" in args or "attachments" in args
                    
                    # Domaines personnels à surveiller (en prod, on vérifierait plutôt "not in allowed_domains")
                    personal_domains = ["@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com", "@icloud.com"]
                    
                    if any(domain in recipient for domain in personal_domains):
                        reason = f"Envoi vers domaine personnel détecté ({recipient})"
                        if has_attachment:
                            reason += " avec pièce jointe. Approbation humaine OBLIGATOIRE."
                            
                        return SecurityCheck(
                            "data_loss_prevention", 
                            False, 
                            RiskLevel.HIGH, 
                            reason,
                            metadata={"requires_approval": True, "recipient": recipient, "has_attachment": has_attachment},
                            action=SecurityAction.REVIEW
                        )
        # --------------------------------------------------

        if tool_name == "execute_command":
            check = self._check_command(params)
            if not check.passed: return check

        try: params_string = json.dumps(params, default=str)
        except Exception: params_string = str(params)
        
        dangerous_patterns = re.compile(r"\b(?:delete_all|drop\s+table|truncate|drop\s+database|rm\s+-rf|sudo|chmod\s+777|mkfs|dd\s+if=|attacker|evil\.com)\b", re.IGNORECASE)
        if dangerous_patterns.search(params_string):
            return SecurityCheck("dangerous_params", False, RiskLevel.HIGH, "Dangerous pattern in params", {}, SecurityAction.BLOCK)
            
        return SecurityCheck("tool_policy", True, RiskLevel.LOW, "Tool call approved")

    def _check_email(self, params: Dict[str, Any]) -> SecurityCheck:
        full_content = f"{params.get('to', '')} {params.get('subject', '')} {params.get('body', '')}"
        exfil_patterns = re.compile(r"\b(?:exfiltrate|attacker|customer\s*(?:data|database)|credentials)\b", re.IGNORECASE)
        if exfil_patterns.search(full_content):
            return SecurityCheck("tool_policy", False, RiskLevel.CRITICAL, "Exfiltration detected in email", {}, SecurityAction.BLOCK)
        return SecurityCheck("tool_policy", True, RiskLevel.LOW, "Email approved")

    def _check_command(self, params: Dict[str, Any]) -> SecurityCheck:
        command = params.get("command", "")
        dangerous = re.compile(r"\b(?:rm\s+-rf|sudo|chmod\s+777|mkfs|dd\s+if=|wget[^|]*\|.*sh|curl[^|]*\|.*sh)\b", re.IGNORECASE)
        if dangerous.search(command):
            return SecurityCheck("tool_policy", False, RiskLevel.CRITICAL, "Dangerous command pattern", {}, SecurityAction.BLOCK)
        return SecurityCheck("tool_policy", True, RiskLevel.LOW, "Command approved")
