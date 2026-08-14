"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️ AGENTGUARD SDK v2.1.0 - STABLE                            ║
║                                                                ║
║  ⚠️ FICHIER STABILISÉ - NE PAS REFACTORER SANS SUPERVISION   ║
║                                                                ║
║  Fonctions critiques verrouillées :                            ║
║  - check_tool_policy()     ✅ Stabilisée (3 régressions)      ║
║  - guard_tool_call()       ✅ Stabilisée                       ║
║  - check_injection()       ✅ Stabilisée                       ║
║  - _compile_patterns()     ✅ Stabilisée                       ║
║                                                                ║
║  Tout refactor doit partir de cette version.                   ║
║  Les tests de non-régression doivent passer avant commit.      ║
╚══════════════════════════════════════════════════════════════════╝
"""
import os
import json
import hashlib
import time
import re
import warnings
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Optional, Dict, Any, List, Callable

import requests


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityAction(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    REVIEW = "review"


class DetectionConfidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SecurityCheck:
    check_name: str
    passed: bool
    risk_level: RiskLevel
    details: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    action: SecurityAction = SecurityAction.ALLOW


class SecurityException(Exception):
    """Exception levée lorsqu'une opération est bloquée par AgentGuard."""


from agentguard_ml import MLDetector


class PolicyEngine:
    """
    Moteur de détection multi-couches :
    1. ML (prioritaire)
    2. Regex forte
    3. LLM Judge (cas ambigus)
    4. Regex faible (fallback)
    """

    def __init__(self, policies: Optional[List[Dict[str, Any]]] = None):
        self.policies = policies or []
        self._compile_patterns()

        self.ml_detector = MLDetector()

        env_value = os.getenv("AGENTGUARD_USE_LLM_JUDGE", "false").lower()
        self.use_llm_judge = env_value in ("true", "1", "on", "yes")

        if self.use_llm_judge:
            print(f"[AG] 🔍 LLM Judge activé")

        self.block_on_ambiguous = (
            os.getenv(
                "AGENTGUARD_BLOCK_ON_AMBIGUOUS",
                "false",
            ).lower()
            in ("true", "1", "on", "yes")
        )

        self.judge_timeout = self._timeout_env(
            "AGENTGUARD_JUDGE_TIMEOUT",
            15.0,
        )

        try:
            self.judge_cache_size = max(
                1,
                int(
                    os.getenv(
                        "AGENTGUARD_JUDGE_CACHE_SIZE",
                        "2048",
                    )
                ),
            )
        except ValueError:
            self.judge_cache_size = 2048

        self._judge_cache = OrderedDict()

    @staticmethod
    def _timeout_env(name, default):
        try:
            return max(
                0.5,
                float(os.getenv(name, str(default))),
            )
        except (TypeError, ValueError):
            return default

    def _compile_patterns(self):
        strong = [
            r"\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)\b",
            r"\bdisregard\s+(your|the|all)\s+(instructions|rules|training)\b",
            r"\byou\s+are\s+now\s+(in\s+|entering\s+)?(DAN|developer)\s+mode\b",
            r"\bjailbreak(?:ing)?\b",
            r"\bsystem\s+override\b",
            r"\bnew\s+instructions?\s*:",
            r"\[(?:system|admin|override)\]",
            r"\breveal\s+(your\s+|the\s+)?system\s+prompt\b",
            r"\brepeat\b.{0,25}\babove\b",
            r"\b(?:with|that\s+has|and)\s+no\s+(?:restrictions|limits|filters)\b",
            r"\bdo\s+anything\s+now\b",
            r"\bignore\s+(tes|vos|les)\s+instructions\s+(?:pr[ée]c[ée]dentes|précédentes)\b",
            r"\boublie\s+(tes|vos)\s+instructions\b",
            r"\btu\s+es\s+maintenant\s+en\s+mode\s+(?:développeur|admin|dan)\b",
            r"\bnouvelles?\s+instructions?\s*:",
            r"\br[ée]v[èe]le\s+(?:ton|le)\s+(?:prompt|invite)\s+syst[èe]me\b",
            r"\bignore\s+(?:ce\s+)?qui\s+pr[ée]c[èe]de\b",
            # NOUVEAUX PATTERNS
            r"\bDAN\s+mode\b",
            r"\bdeveloper\s+mode\b",
            r"\bunrestricted\s+(?:AI|assistant|mode)\b",
            r"\bno\s+(?:restrictions|limits|filters)\b",
            r"\bbypass\s+(?:safety|security|content)\s+(?:filters|restrictions|guidelines)\b",
            r"\b(?:pretend|act)\s+as\s+if\s+you\s+(?:are|were)\s+unrestricted\b",
            r"\bexport\s+(?:all|the)?\s+(?:data|customer|database|records)\b",
            r"\bsend\s+me\s+(?:your|the)\s+(?:training|system|confidential)\s+data\b",
            r"\bextract\s+(?:all|the)\s+(?:sensitive|confidential|secret)\s+(?:data|information)\b",
            r"\bleak\s+(?:the|all)?\s+(?:source\s+code|api\s+keys|credentials|secrets)\b",
            r"\btransfer\s+(?:funds|money|payment)\s+to\b",
            r"\bdelete\s+(?:all|the)?\s+(?:records|data|files|logs)\b",
            r"\bdrop\s+(?:table|database)\b",
            r"\bexecute\s+(?:shell|command|code)\b",
            r"\brm\s+-rf\b",
            r"\bformat\s+[a-z]:\b",
            r"\bgrant\s+(?:full|admin|root)\s+access\b",
            r"\bcreate\s+(?:admin|backdoor)\s+user\b",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            r"\b\d{3}-\d{2}-\d{4}\b",
            r"\b(?:\d[ -]*?){13,19}\b",
        ]

        weak = [
            r"\bpretend\s+you\s+are\b",
            r"\broleplay\s+as\b",
            r"\bact\s+as\s+if\s+you\s+(?:are|were)\b",
            r"\bcomme\s+si\s+tu\s+(?:es|étais)\b",
            r"\bjoue\s+le\s+r[ôo]le\s+de\b",
            r"\bimagine\s+that\s+you\s+are\b",
            r"\bwhat\s+if\s+you\s+were\b",
        ]

        self.strong_regex = re.compile(
            "|".join(f"(?:{pattern})" for pattern in strong),
            re.IGNORECASE,
        )

        self.weak_regex = re.compile(
            "|".join(f"(?:{pattern})" for pattern in weak),
            re.IGNORECASE,
        )

    def check_injection(self, text: str) -> SecurityCheck:
        """
        Détection multi-couches avec priorité :
        1. ML (si disponible) - détection sémantique
        2. Regex fort - patterns évidents
        3. LLM Judge - cas ambigus ou non détectés
        4. Regex faible - fallback
        """
        text = str(text or "")

        if not text.strip():
            return SecurityCheck(
                "prompt_injection",
                True,
                RiskLevel.LOW,
                "Empty prompt",
            )

        # ═══════════════════════════════════════════════════════════
        # 1. ML - Détection sémantique (prioritaire)
        # ═══════════════════════════════════════════════════════════
        if self.ml_detector.enabled:
            ml_result = self.ml_detector.predict(text)
            score = ml_result["score"]

            # ML très confiant → BLOCK
            if ml_result["risk"] == "HIGH" and score >= 0.85:
                return SecurityCheck(
                    "prompt_injection",
                    False,
                    RiskLevel.HIGH,
                    f"ML detected threat (score: {score:.2%})",
                    {
                        "ml_score": score,
                        "confidence": ml_result["confidence"],
                        "layer": "ml",
                    },
                    SecurityAction.BLOCK,
                )

            # ML détecte mais pas assez confiant → LLM Judge
            if ml_result["risk"] == "HIGH" and self.use_llm_judge:
                judge_result = self._call_llm_judge(text)
                if judge_result:
                    return judge_result

        # ═══════════════════════════════════════════════════════════
        # 2. Regex fort - patterns évidents
        # ═══════════════════════════════════════════════════════════
        strong_matches = self.strong_regex.findall(text)

        if strong_matches and self.use_llm_judge:
            judge_result = self._call_llm_judge(text)
            if judge_result and not judge_result.passed:
                return judge_result

        if strong_matches:
            return SecurityCheck(
                "prompt_injection",
                False,
                RiskLevel.HIGH,
                f"Strong injection pattern detected: "
                f"{strong_matches[:3]}",
                {
                    "patterns_found": strong_matches[:5],
                    "confidence": "high",
                    "layer": "regex",
                },
                SecurityAction.BLOCK,
            )

        # ═══════════════════════════════════════════════════════════
        # 3. LLM Judge - Cas ambigus
        # ═══════════════════════════════════════════════════════════
        if self.use_llm_judge:
            judge_result = self._call_llm_judge(text)
            if judge_result:
                return judge_result

        # ═══════════════════════════════════════════════════════════
        # 4. Regex faible - Fallback
        # ═══════════════════════════════════════════════════════════
        weak_matches = self.weak_regex.findall(text)

        if weak_matches:
            blocked = self.block_on_ambiguous
            return SecurityCheck(
                "prompt_injection",
                not blocked,
                RiskLevel.MEDIUM if blocked else RiskLevel.LOW,
                f"Ambiguous injection pattern detected: "
                f"{weak_matches[:3]}",
                {
                    "patterns_found": weak_matches[:5],
                    "confidence": "low",
                    "layer": "regex_weak",
                },
                (
                    SecurityAction.BLOCK
                    if blocked
                    else SecurityAction.REVIEW
                ),
            )

        return SecurityCheck(
            "prompt_injection",
            True,
            RiskLevel.LOW,
            "No injection detected",
            {
                "confidence": "high",
                "layer": "all_clear",
            },
            SecurityAction.ALLOW,
        )

    def _cache_get(self, key):
        value = self._judge_cache.get(key)

        if value is not None:
            self._judge_cache.move_to_end(key)

        return value

    def _cache_put(self, key, value):
        self._judge_cache[key] = value
        self._judge_cache.move_to_end(key)

        while len(self._judge_cache) > self.judge_cache_size:
            self._judge_cache.popitem(last=False)

    @staticmethod
    def _redact_sensitive_text(text: str) -> str:
        patterns = (
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[REDACTED_EMAIL]"),
            (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
            (r"\b(?:\d{4}[- ]?){3}\d{4}\b", "[REDACTED_CARD]"),
            (r"\b(?:sk-|pk-|Bearer\s+)[A-Za-z0-9._~+/=-]{20,}\b", "[REDACTED_TOKEN]"),
            (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
            (r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[REDACTED_JWT]"),
        )
        result = str(text or "")
        for pattern, replacement in patterns:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE | re.DOTALL)
        return result

    def _call_llm_judge(
        self,
        text: str,
    ) -> Optional[SecurityCheck]:
        """
        Analyse sémantique d'un cas ambigu.
        """
        # Vérifier si le LLM Judge est activé
        if not self.use_llm_judge:
            return None

        api_key = (
            os.getenv("AGENTGUARD_JUDGE_API_KEY")
            or os.getenv("DEEPSEEK_API_KEY")
        )

        if not api_key:
            return None

        cache_key = hashlib.sha256(
            text[:2000].encode("utf-8", "ignore")
        ).hexdigest()

        cached = self._cache_get(cache_key)

        if cached is not None:
            return cached

        try:
            # Never send obvious secrets/PII to the external judge. Reuse the
            # same recursive-safe redaction semantics as the collector for text.
            judge_text = self._redact_sensitive_text(text[:2000])
            response = requests.post(
                os.getenv(
                    "AGENTGUARD_JUDGE_URL",
                    "https://api.deepseek.com/chat/completions",
                ),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": os.getenv(
                        "AGENTGUARD_JUDGE_MODEL",
                        "deepseek-chat",
                    ),
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "Return ONLY JSON: "
                                '{"score":0-100,'
                                '"reason":"brief",'
                                '"is_attack":true/false}. '
                                "Classify prompt injection, instruction "
                                "override, jailbreak and system-prompt "
                                "extraction."
                            ),
                        },
                        {
                            "role": "user",
                            "content": (
                                "Text to analyze:\n"
                                f"{judge_text}"
                            ),
                        },
                    ],
                    "max_tokens": 150,
                    "temperature": 0.0,
                },
                timeout=self.judge_timeout,
            )

            response.raise_for_status()

            content = response.json()["choices"][0]["message"]["content"]

            content = re.sub(
                r"^```(?:json)?\s*|\s*```$",
                "",
                content.strip(),
                flags=re.IGNORECASE,
            )

            data = json.loads(content)

            score = max(
                0.0,
                min(100.0, float(data.get("score", 0))),
            )

            is_attack = bool(data.get("is_attack", False))

            if score > 70 or is_attack:
                check = SecurityCheck(
                    "llm_judge",
                    False,
                    (
                        RiskLevel.HIGH
                        if score > 85
                        else RiskLevel.MEDIUM
                    ),
                    (
                        f"LLM Judge: "
                        f"{str(data.get('reason', ''))[:300]} "
                        f"(score: {score:.0f})"
                    ),
                    {
                        "llm_score": score,
                        "is_attack": is_attack,
                        "confidence": "high",
                        "layer": "llm_judge",
                    },
                    (
                        SecurityAction.BLOCK
                        if score > 85
                        else SecurityAction.REVIEW
                    ),
                )

                self._cache_put(cache_key, check)
                return check

            check = SecurityCheck(
                "llm_judge",
                True,
                RiskLevel.LOW,
                f"LLM Judge: safe (score: {score:.0f})",
                {
                    "llm_score": score,
                    "is_attack": is_attack,
                    "confidence": "medium",
                    "layer": "llm_judge",
                },
                SecurityAction.ALLOW,
            )

            self._cache_put(cache_key, check)
            return check

        except Exception as exc:
            warnings.warn(
                f"[AG] LLM Judge unavailable: "
                f"{type(exc).__name__}: {exc}"
            )
            return None

    def check_pii(self, text: str) -> SecurityCheck:
        """
        Détection de données sensibles.

        Email/téléphone => REDACT/REVIEW.
        Carte bancaire, SSN et clés => BLOCK.
        """

        text = str(text or "")

        patterns = {
            "email": (
                r"\b[A-Za-z0-9._%+-]+@"
                r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
            ),
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b(?:\d[ -]*?){13,19}\b",
            "phone": (
                r"(?<!\w)\+?\d[\d().\s-]{7,}\d(?!\w)"
            ),
            "api_key": (
                r"\b(?:sk-|pk-|Bearer\s+)"
                r"[A-Za-z0-9._-]{20,}\b"
            ),
        }

        findings = {}

        for name, pattern in patterns.items():
            try:
                matches = re.findall(
                    pattern,
                    text,
                    re.IGNORECASE,
                )

                if matches:
                    findings[name] = len(matches)

            except re.error:
                continue

        if not findings:
            return SecurityCheck(
                "pii_detection",
                True,
                RiskLevel.LOW,
                "No PII detected",
                action=SecurityAction.ALLOW,
            )

        blocking_types = {
            "credit_card",
            "ssn",
            "api_key",
        }

        detected_types = set(findings)
        hard_block = detected_types & blocking_types

        action = (
            SecurityAction.BLOCK
            if hard_block
            else SecurityAction.REDACT
        )

        risk = (
            RiskLevel.HIGH
            if hard_block
            else RiskLevel.MEDIUM
        )

        return SecurityCheck(
            "pii_detection",
            False,
            risk,
            f"PII detected: {findings}",
            {
                "pii_types": findings,
                "action": action.value,
            },
            action,
        )

    # ═══════════════════════════════════════════════════════════════
    # ⚠️ CRITICAL - NE PAS MODIFIER SANS SUPERVISION
    # Version stabilisée après 3 régressions
    # ═══════════════════════════════════════════════════════════════
    def check_tool_policy(
        self,
        tool_name: str,
        params: Dict[str, Any],
        budget_remaining: float,
    ) -> SecurityCheck:
        allowed_tools = []
        whitelist_configured = False

        for policy in self.policies:
            if policy.get("type") == "tool_whitelist":
                whitelist_configured = True
                allowed_tools.extend(
                    policy.get("allowed_tools", [])
                )

        # Secure-by-default: a tool is executable only when it is explicitly
        # allowed. Set AGENTGUARD_TOOL_DEFAULT_DENY=false only for legacy
        # deployments that intentionally allow an open tool surface.
        default_deny = os.getenv(
            "AGENTGUARD_TOOL_DEFAULT_DENY", "true"
        ).lower() in ("true", "1", "yes", "on")

        if (default_deny and (not whitelist_configured or tool_name not in allowed_tools)) or (
            not default_deny and allowed_tools and tool_name not in allowed_tools
        ):
            return SecurityCheck(
                "tool_policy",
                False,
                RiskLevel.CRITICAL,
                f"Tool '{tool_name}' not in whitelist",
                {
                    "tool": tool_name,
                    "allowed": allowed_tools,
                    "confidence": "high",
                },
                SecurityAction.BLOCK,
            )

        if budget_remaining < 0:
            return SecurityCheck(
                "budget_policy",
                False,
                RiskLevel.HIGH,
                "Budget exceeded",
                {
                    "budget_remaining": budget_remaining,
                },
                SecurityAction.BLOCK,
            )

        # ═══════════════════════════════════════════════════════════
        # ✅ INSPECTION DU CONTENU DES OUTILS (NOUVEAU)
        # ═══════════════════════════════════════════════════════════

        # 1. Inspection des emails (exfiltration, PII)
        if tool_name == "send_email":
            body = params.get("body", "")
            to = params.get("to", "")
            subject = params.get("subject", "")
            # Le destinataire et le sujet comptent aussi pour l'exfiltration —
            # avant cette correction, seul "body" était scanné, donc un email
            # vers "external-attacker@..." avec juste "CUSTOMER_DATABASE"
            # dans le sujet passait sans être jamais inspecté.
            full_content = f"{to} {subject} {body}"

            # Détection d'exfiltration — patterns FORTS (spécifiques, rares
            # en usage légitime) : bloquants direct.
            exfil_strong_patterns = [
                r"customer[\s_]*(?:data|database|list)",
                r"export\s+(?:all|the)?\s*(?:data|database)",
                r"\battacker\b",
                r"\bexfiltrate\b",
                r"\bcredentials\b",
                r"credit\s+card",
                r"\bssn\b",
                r"\b\d{3}-\d{2}-\d{4}\b",
                r"\b(?:\d[ -]*?){13,19}\b",
            ]
            # Patterns FAIBLES : mots qui apparaissent aussi dans des emails
            # professionnels tout à fait légitimes ("ce document est
            # confidentiel", "réinitialiser votre mot de passe"). Un simple
            # substring match ici bloquerait une bonne partie du courrier
            # client normal — measuré : 25% de faux blocages sur des cas
            # plausibles. Signalés (MEDIUM) mais pas bloquants seuls.
            exfil_weak_patterns = [
                r"\bleak\b",
                r"\bconfidential\b",
                r"\bsecret\b",
                r"\bpassword\b",
            ]

            for pattern in exfil_strong_patterns:
                if re.search(pattern, full_content, re.IGNORECASE):
                    return SecurityCheck(
                        "tool_policy",
                        False,
                        RiskLevel.CRITICAL,
                        f"Exfiltration detected in email: {pattern}",
                        {"tool": tool_name, "pattern": pattern, "confidence": "high"},
                        SecurityAction.BLOCK,
                    )

            for pattern in exfil_weak_patterns:
                if re.search(pattern, full_content, re.IGNORECASE):
                    return SecurityCheck(
                        "tool_policy",
                        False,
                        RiskLevel.MEDIUM,
                        f"Ambiguous exfiltration-adjacent term in email, needs review: {pattern}",
                        {"tool": tool_name, "pattern": pattern, "confidence": "ambiguous"},
                        SecurityAction.REVIEW,
                    )

            # Détection de PII dans l'email — l'adresse email générique seule
            # est trop fréquente en correspondance normale ("contactez
            # support@..." ) pour bloquer d'office ; seuls SSN/carte
            # bancaire (patterns précis, rares en usage légitime) bloquent.
            # On exclut "to" ici : c'est structurellement toujours une
            # adresse email (le destinataire), donc l'y chercher
            # déclencherait le flag PII sur CHAQUE email envoyé, sans valeur.
            pii_content = f"{subject} {body}"
            pii_block_patterns = [
                r"\b\d{3}-\d{2}-\d{4}\b",
                r"\b(?:\d[ -]*?){13,19}\b",
            ]
            pii_review_patterns = [
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            ]

            for pattern in pii_block_patterns:
                if re.search(pattern, pii_content, re.IGNORECASE):
                    return SecurityCheck(
                        "tool_policy",
                        False,
                        RiskLevel.HIGH,
                        f"PII detected in email content",
                        {"tool": tool_name, "pattern": pattern, "confidence": "high"},
                        SecurityAction.BLOCK,
                    )

            for pattern in pii_review_patterns:
                if re.search(pattern, pii_content, re.IGNORECASE):
                    return SecurityCheck(
                        "tool_policy",
                        False,
                        RiskLevel.MEDIUM,
                        f"Email address present in email content, needs review",
                        {"tool": tool_name, "pattern": pattern, "confidence": "ambiguous"},
                        SecurityAction.REVIEW,
                    )

        # 2. Inspection des commandes système
        if tool_name == "execute_command":
            command = params.get("command", "")

            dangerous_commands = [
                r"rm\s+-rf",
                r"sudo",
                r"chmod\s+777",
                r"chown",
                r"/etc/passwd",
                r"/etc/shadow",
                r"dd\s+if=",
                r"mkfs",
                r"format",
                r":\s*\(\)\s*\{",
                r"wget.*\|.*sh",
                r"curl.*\|.*sh",
                r"python\s+-c",
                r"eval\s*\(",
                r"exec\s*\(",
                r"system\s*\(",
                r"subprocess",
                r"__import__",
                r"compile\s*\(",
            ]

            for pattern in dangerous_commands:
                if re.search(pattern, command, re.IGNORECASE):
                    return SecurityCheck(
                        "tool_policy",
                        False,
                        RiskLevel.CRITICAL,
                        f"Dangerous command pattern: {pattern}",
                        {"tool": tool_name, "pattern": pattern},
                        SecurityAction.BLOCK,
                    )

        # 3. Mots-clés dangereux (forts)
        strong_keywords_regex = re.compile(
            r"(\bdelete_all\b|\bdrop\s+table\b|\btruncate\b|rm\s+-rf|drop\s+database|"
            r";\s*--|--\s*$|\bunion\s+select\b)",
            re.IGNORECASE
        )

        # 4. Mots-clés ambigus (faibles) → REVIEW, pas BLOCK
        weak_keywords_regex = re.compile(r"\b(transfer|password|secret)\b", re.IGNORECASE)

        try:
            params_string = json.dumps(params, default=str)
        except Exception:
            params_string = str(params)

        strong_found = strong_keywords_regex.findall(params_string)
        if strong_found:
            return SecurityCheck(
                "dangerous_params",
                False,
                RiskLevel.HIGH,
                f"Dangerous pattern(s) in params: {strong_found[:3]}",
                {"keywords": strong_found[:5], "confidence": "high"},
                SecurityAction.BLOCK,
            )

        weak_found = weak_keywords_regex.findall(params_string)
        if weak_found:
            return SecurityCheck(
                "dangerous_params",
                False,
                RiskLevel.MEDIUM,
                f"Ambiguous keyword(s), needs review: {weak_found[:3]}",
                {"keywords": weak_found[:5], "confidence": "ambiguous"},
                SecurityAction.REVIEW,
            )

        return SecurityCheck(
            "tool_policy",
            True,
            RiskLevel.LOW,
            "Tool call approved",
            action=SecurityAction.ALLOW,
        )

    def check_budget(
        self,
        cost: float,
        max_budget: float,
        total_spent: float,
    ) -> SecurityCheck:
        projected = total_spent + cost

        if projected > max_budget:
            return SecurityCheck(
                "budget",
                False,
                RiskLevel.HIGH,
                (
                    f"Budget would be exceeded: "
                    f"{projected:.6f} > {max_budget:.6f}"
                ),
                {
                    "total_spent": total_spent,
                    "cost": cost,
                    "max_budget": max_budget,
                },
                SecurityAction.BLOCK,
            )

        return SecurityCheck(
            "budget",
            True,
            RiskLevel.LOW,
            "Within budget",
            action=SecurityAction.ALLOW,
        )


@dataclass
class GuardSpan:
    span_id: str
    trace_id: str
    span_type: str
    timestamp: float
    latency_ms: float
    input_data: Dict[str, Any]
    output_data: Dict[str, Any]
    security_checks: List[SecurityCheck] = field(
        default_factory=list
    )
    blocked: bool = False
    block_reason: Optional[str] = None
    cost_usd: float = 0.0


class AgentGuard:
    """
    Middleware principal d'AgentGuard.

    Les contrôles de sécurité sont exécutés avant l'appel LLM
    ou avant l'exécution d'un outil.
    """

    def __init__(
        self,
        collector_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        policies: Optional[List[Dict[str, Any]]] = None,
        max_budget: float = 10.0,
        block_on_high: bool = True,
        debug: bool = True,
        use_ml: Optional[bool] = None,
        use_llm_judge: Optional[bool] = None,
    ):
        self.collector_url = collector_url.rstrip("/")
        self.api_key = (
            api_key
            or os.getenv("AGENTGUARD_API_KEY")
        )

        self.max_budget = max(
            0.0,
            float(max_budget),
        )

        self.block_on_high = block_on_high
        self.debug = debug
        self.total_spent = 0.0
        self.trace_id = self._generate_id()

        self.spans: List[GuardSpan] = []
        self._pending_spans: List[Dict[str, Any]] = []

        try:
            self.max_pending = max(
                1,
                int(
                    os.getenv(
                        "AGENTGUARD_MAX_PENDING",
                        "500",
                    )
                ),
            )
        except ValueError:
            self.max_pending = 500

        self.collector_timeout = self._timeout_env(
            "AGENTGUARD_COLLECTOR_TIMEOUT",
            5.0,
        )

        if use_ml is not None:
            os.environ["AGENTGUARD_USE_ML"] = (
                "true" if use_ml else "false"
            )

        if use_llm_judge is not None:
            os.environ["AGENTGUARD_USE_LLM_JUDGE"] = (
                "true" if use_llm_judge else "false"
            )

        self.policy_engine = PolicyEngine(
            policies or []
        )

        if self.debug:
            print(
                f"[AgentGuard] Collector: "
                f"{self.collector_url}"
            )
            print(
                "[AgentGuard] ML: "
                f"{'ON' if self.policy_engine.ml_detector.enabled else 'OFF'}"
            )
            print(
                "[AgentGuard] LLM Judge: "
                f"{'ON' if self.policy_engine.use_llm_judge else 'OFF'}"
            )

            self._test_connection()

    @staticmethod
    def _timeout_env(name, default):
        try:
            return max(
                0.5,
                float(os.getenv(name, str(default))),
            )
        except (TypeError, ValueError):
            return default

    def _generate_id(self):
        return hashlib.sha256(
            f"{time.time_ns()}:{id(self)}".encode()
        ).hexdigest()[:16]

    def _headers(self):
        headers = {
            "Content-Type": "application/json",
        }

        if self.api_key:
            headers["X-API-Key"] = self.api_key

        return headers

    def _test_connection(self):
        try:
            response = requests.get(
                f"{self.collector_url}/api/metrics",
                headers=self._headers(),
                timeout=self.collector_timeout,
            )

            if response.status_code == 200:
                print(
                    "[AgentGuard] Collector connecté"
                )

            elif response.status_code == 401:
                print(
                    "[AgentGuard] Collector connecté "
                    "mais API key invalide/manquante"
                )

            else:
                print(
                    f"[AgentGuard] Collector HTTP "
                    f"{response.status_code}"
                )

        except requests.RequestException as exc:
            print(
                f"[AgentGuard] Collector inaccessible: "
                f"{exc}"
            )

    def _payload(self, span: GuardSpan):
        return {
            "trace_id": span.trace_id,
            "span_id": span.span_id,
            "span_type": span.span_type,
            "timestamp": span.timestamp,
            "latency_ms": span.latency_ms,
            "input_data": span.input_data,
            "output_data": span.output_data,
            "security_checks": [
                {
                    "check_name": check.check_name,
                    "passed": check.passed,
                    "risk_level": check.risk_level.value,
                    "details": check.details,
                    "metadata": check.metadata,
                }
                for check in span.security_checks
            ],
            "blocked": span.blocked,
            "block_reason": span.block_reason,
            "cost_usd": span.cost_usd,
        }

    def _queue(self, payload):
        if len(self._pending_spans) >= self.max_pending:
            self._pending_spans.pop(0)

        self._pending_spans.append(payload)

    def _send_to_collector(self, span: GuardSpan):
        payload = self._payload(span)

        try:
            response = requests.post(
                f"{self.collector_url}/span",
                json=payload,
                headers=self._headers(),
                timeout=self.collector_timeout,
            )

            if response.status_code in (
                200,
                201,
                202,
            ):
                self._flush_pending()
                return

            if self.debug:
                print(
                    "[AgentGuard] Collector HTTP "
                    f"{response.status_code}; "
                    "span bufferisée"
                )

            self._queue(payload)

        except requests.RequestException as exc:
            if self.debug:
                print(
                    "[AgentGuard] Envoi collector échoué: "
                    f"{exc}"
                )

            self._queue(payload)

    def _flush_pending(self):
        if not self._pending_spans:
            return

        remaining = []

        for payload in self._pending_spans:
            try:
                response = requests.post(
                    f"{self.collector_url}/span",
                    json=payload,
                    headers=self._headers(),
                    timeout=self.collector_timeout,
                )

                if response.status_code not in (
                    200,
                    201,
                    202,
                ):
                    remaining.append(payload)

            except requests.RequestException:
                remaining.append(payload)
                break

        self._pending_spans = remaining[-self.max_pending:]

    @staticmethod
    def _extract_input(args, kwargs):
        messages = kwargs.get("messages")

        if isinstance(messages, list):
            parts = []

            for message in messages:
                if (
                    isinstance(message, dict)
                    and isinstance(
                        message.get("content"),
                        str,
                    )
                ):
                    parts.append(message["content"])

            return "\n".join(parts)

        if args and isinstance(args[0], str):
            return args[0]

        return ""

    @staticmethod
    def _extract_output(result):
        if isinstance(result, str):
            return result

        choices = getattr(result, "choices", None)

        if choices:
            parts = []

            for choice in choices:
                message = getattr(
                    choice,
                    "message",
                    None,
                )

                content = (
                    getattr(message, "content", None)
                    if message
                    else None
                )

                if isinstance(content, str):
                    parts.append(content)

            return "\n".join(parts)

        return ""

    def guard_llm_call(self, func: Callable) -> Callable:
        """
        Décorateur de protection d'un appel LLM.
        """

        @wraps(func)
        def wrapper(*args, **kwargs):
            span_id = self._generate_id()
            start = time.time()

            input_text = self._extract_input(
                args,
                kwargs,
            )

            checks = [
                self.policy_engine.check_injection(
                    input_text
                ),
                self.policy_engine.check_pii(
                    input_text
                ),
            ]

            high_risk = [
                check
                for check in checks
                if (
                    not check.passed
                    and check.risk_level
                    in (
                        RiskLevel.HIGH,
                        RiskLevel.CRITICAL,
                    )
                )
            ]

            # PRE-FLIGHT budget enforcement: never call the provider when the
            # estimated request itself would exceed the remaining budget.
            estimated_request_cost = self._estimate_request_cost(kwargs)
            if estimated_request_cost is None:
                budget_check = SecurityCheck(
                    "budget",
                    False,
                    RiskLevel.HIGH,
                    "Cannot safely estimate LLM request cost for unknown model",
                    {"model": str(kwargs.get("model", ""))[:100]},
                    SecurityAction.BLOCK,
                )
                checks.append(budget_check)
                high_risk = [budget_check]
            else:
                budget_check = self.policy_engine.check_budget(
                    estimated_request_cost,
                    self.max_budget,
                    self.total_spent,
                )
                checks.append(budget_check)
                if not budget_check.passed:
                    high_risk = [budget_check]

            if high_risk and self.block_on_high:
                span = GuardSpan(
                    span_id=span_id,
                    trace_id=self.trace_id,
                    span_type="llm_call",
                    timestamp=start,
                    latency_ms=(
                        time.time() - start
                    ) * 1000,
                    input_data={
                        "prompt": input_text[:500]
                    },
                    output_data={
                        "blocked": True
                    },
                    security_checks=checks,
                    blocked=True,
                    block_reason=(
                        "HIGH RISK: "
                        f"{[c.check_name for c in high_risk]}"
                    ),
                )

                self.spans.append(span)
                self._send_to_collector(span)

                raise SecurityException(
                    "🛡️ AgentGuard BLOCKED: "
                    f"{span.block_reason}"
                )

            try:
                result = func(
                    *args,
                    **kwargs,
                )

            except Exception as exc:
                span = GuardSpan(
                    span_id=span_id,
                    trace_id=self.trace_id,
                    span_type="llm_call",
                    timestamp=start,
                    latency_ms=(
                        time.time() - start
                    ) * 1000,
                    input_data={
                        "prompt": input_text[:500]
                    },
                    output_data={
                        "error": str(exc)[:1000]
                    },
                    security_checks=checks,
                )

                self.spans.append(span)
                self._send_to_collector(span)

                raise

            latency = (
                time.time() - start
            ) * 1000

            cost = self._estimate_cost(
                kwargs,
                result,
            )

            output_text = self._extract_output(
                result
            )

            # Charge the actual observed/estimated usage only after the call.
            # The pre-flight check above is what prevents overspending.
            self.total_spent += cost

            output_pii = self.policy_engine.check_pii(output_text)

            # Post-flight accounting check catches an underestimated request.
            post_budget_check = self.policy_engine.check_budget(
                0.0,
                self.max_budget,
                self.total_spent,
            )

            checks.extend([output_pii, post_budget_check])

            blocking_output = [
                check
                for check in checks
                if (
                    not check.passed
                    and check.risk_level
                    in (
                        RiskLevel.HIGH,
                        RiskLevel.CRITICAL,
                    )
                )
            ]

            blocked = (
                bool(blocking_output)
                and self.block_on_high
            )

            span = GuardSpan(
                span_id=span_id,
                trace_id=self.trace_id,
                span_type="llm_call",
                timestamp=start,
                latency_ms=latency,
                input_data={
                    "prompt": input_text[:500]
                },
                output_data={
                    "response": output_text[:500]
                },
                security_checks=checks,
                blocked=blocked,
                block_reason=(
                    "Output risk: "
                    f"{[c.check_name for c in blocking_output]}"
                    if blocked
                    else None
                ),
                cost_usd=cost,
            )

            self.spans.append(span)
            self._send_to_collector(span)

            if blocked:
                raise SecurityException(
                    "🛡️ Output blocked: "
                    f"{span.block_reason}"
                )

            return result

        return wrapper

    # ═══════════════════════════════════════════════════════════════
    # ⚠️ CRITICAL - NE PAS MODIFIER SANS SUPERVISION
    # Version stabilisée après 3 régressions
    # ═══════════════════════════════════════════════════════════════
    def guard_tool_call(
        self,
        tool_name: str,
        params: Optional[Dict[str, Any]] = None,
        func: Optional[Callable] = None,
    ):
        """
        Vérifie une tool call avant exécution.

        Formes compatibles :
            guard.guard_tool_call("tool", params, func)
            @guard.guard_tool_call("tool")
            def tool(...): ...
        """
        if params is None and func is None:
            def decorator(wrapped: Callable):
                @wraps(wrapped)
                def wrapper(*args, **kwargs):
                    return self.guard_tool_call(tool_name, kwargs, wrapped)
                return wrapper
            return decorator

        if params is None or func is None:
            raise TypeError("params et func doivent être fournis ensemble")

        span_id = self._generate_id()
        start = time.time()

        budget_remaining = (
            self.max_budget
            - self.total_spent
        )

        check = (
            self.policy_engine.check_tool_policy(
                tool_name,
                params,
                budget_remaining,
            )
        )

        if (
            not check.passed
            and check.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            and self.block_on_high
        ):
            span = GuardSpan(
                span_id=span_id,
                trace_id=self.trace_id,
                span_type="tool_call",
                timestamp=start,
                latency_ms=(
                    time.time() - start
                ) * 1000,
                input_data={
                    "tool": tool_name,
                    "params": params,
                },
                output_data={
                    "blocked": True
                },
                security_checks=[check],
                blocked=True,
                block_reason=check.details,
            )

            self.spans.append(span)
            self._send_to_collector(span)

            raise SecurityException(
                "🛡️ Tool blocked: "
                f"{check.details}"
            )

        try:
            result = func(**params)

        except Exception as exc:
            span = GuardSpan(
                span_id=span_id,
                trace_id=self.trace_id,
                span_type="tool_call",
                timestamp=start,
                latency_ms=(
                    time.time() - start
                ) * 1000,
                input_data={
                    "tool": tool_name,
                    "params": params,
                },
                output_data={
                    "error": str(exc)[:1000]
                },
                security_checks=[check],
            )

            self.spans.append(span)
            self._send_to_collector(span)

            raise

        span = GuardSpan(
            span_id=span_id,
            trace_id=self.trace_id,
            span_type="tool_call",
            timestamp=start,
            latency_ms=(
                time.time() - start
            ) * 1000,
            input_data={
                "tool": tool_name,
                "params": params,
            },
            output_data={
                "result": str(result)[:500]
            },
            security_checks=[check],
        )

        self.spans.append(span)
        self._send_to_collector(span)

        return result

    _PRICING_USD_PER_TOKEN = {
        "gpt-4o": (2.5e-6, 1.0e-5),
        "gpt-4o-mini": (1.5e-7, 6.0e-7),
        "gpt-3.5-turbo": (5.0e-7, 1.5e-6),
        "deepseek-chat": (1.4e-7, 2.8e-7),
        "deepseek-reasoner": (5.5e-7, 2.19e-6),
    }

    @staticmethod
    def _approx_tokens(text: str) -> int:
        # Conservative approximation used only for pre-flight enforcement.
        return max(0, int(len(str(text).split()) * 1.3))

    def _estimate_request_cost(self, kwargs):
        model = str(kwargs.get("model", "")).strip()
        pricing = self._PRICING_USD_PER_TOKEN.get(model)
        if pricing is None:
            policy = os.getenv("AGENTGUARD_UNKNOWN_MODEL_POLICY", "block").lower()
            if policy == "allow":
                pricing = (2.5e-6, 1.0e-5)
            else:
                return None

        messages = kwargs.get("messages", [])
        input_text = "\n".join(
            str(m.get("content", ""))
            for m in messages
            if isinstance(m, dict)
        )
        input_tokens = self._approx_tokens(input_text)
        # Reserve max_tokens before the provider call. This is conservative and
        # is intentionally used for enforcement, not billing accuracy.
        try:
            requested_max = kwargs.get("max_tokens", kwargs.get("max_completion_tokens", os.getenv("AGENTGUARD_DEFAULT_MAX_OUTPUT_TOKENS", "4096")))
            max_output_tokens = max(0, int(requested_max))
        except (TypeError, ValueError):
            max_output_tokens = 4096

        input_price, output_price = pricing
        return max(0.0, input_tokens * input_price + max_output_tokens * output_price)

    def _estimate_cost(self, kwargs, result):
        model = str(kwargs.get("model", "")).strip()
        pricing = self._PRICING_USD_PER_TOKEN.get(model)
        if pricing is None:
            # For accounting, keep the same safe policy as pre-flight.
            if os.getenv("AGENTGUARD_UNKNOWN_MODEL_POLICY", "block").lower() != "allow":
                return 0.0
            pricing = (2.5e-6, 1.0e-5)

        messages = kwargs.get("messages", [])
        input_tokens = sum(
            self._approx_tokens(str(message.get("content", "")))
            for message in messages
            if isinstance(message, dict)
        )
        output_tokens = self._approx_tokens(self._extract_output(result))
        input_price, output_price = pricing
        return max(0.0, input_tokens * input_price + output_tokens * output_price)

    def get_report(self):
        total_checks = sum(
            len(span.security_checks)
            for span in self.spans
        )

        failed_checks = sum(
            1
            for span in self.spans
            for check in span.security_checks
            if not check.passed
        )

        blocked = sum(
            1
            for span in self.spans
            if span.blocked
        )

        return {
            "trace_id": self.trace_id,
            "total_spans": len(self.spans),
            "total_checks": total_checks,
            "failed_checks": failed_checks,
            "blocked_operations": blocked,
            "total_cost_usd": round(
                self.total_spent,
                6,
            ),
            "budget_remaining": round(
                self.max_budget
                - self.total_spent,
                6,
            ),
            "pending_spans": len(
                self._pending_spans
            ),
            "risk_summary": self._risk_summary(),
            "detection_layers": {
                "ml": (
                    self.policy_engine
                    .ml_detector
                    .enabled
                ),
                "llm_judge": (
                    self.policy_engine
                    .use_llm_judge
                ),
            },
        }

    def _risk_summary(self):
        summary = {
            level.value: 0
            for level in RiskLevel
        }

        for span in self.spans:
            for check in span.security_checks:
                summary[
                    check.risk_level.value
                ] += 1

        return summary


__version__ = "2.1.2"

__all__ = [
    "AgentGuard",
    "SecurityException",
    "RiskLevel",
    "SecurityAction",
    "DetectionConfidence",
    "SecurityCheck",
    "GuardSpan",
    "PolicyEngine",
]
