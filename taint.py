"""
AgentGuard Taint Tracking — Data flow security
Trace la classification des données à travers les appels d'outils.

Classifications :
  PUBLIC       : données publiques, safe à exposer
  INTERNAL     : données internes, usage restreint
  CONFIDENTIAL : données clients/sensibles
  SECRET       : clés API, passwords, tokens
  UNTRUSTED    : données externes non vérifiées (web, user input)
  MALICIOUS    : injection détectée, à bloquer

Flux interdits (par défaut) :
  SECRET → EXTERNAL_SINK        = DENY
  CONFIDENTIAL → EXTERNAL_SINK  = REQUIRE_APPROVAL
  UNTRUSTED → TOOL_DANGEREUX    = DENY
  MALICIOUS → anywhere          = DENY
"""
import re
import json
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set


class TaintLevel(Enum):
    """Niveaux de classification, du plus safe au plus dangereux."""
    PUBLIC = 0
    INTERNAL = 10
    CONFIDENTIAL = 20
    SECRET = 30
    UNTRUSTED = 40
    MALICIOUS = 100

    def __ge__(self, other):
        return self.value >= other.value

    def __gt__(self, other):
        return self.value > other.value


class SinkType(Enum):
    """Types de destinations (sinks) pour les données."""
    INTERNAL = "internal"           # Usage interne (LLM, calcul)
    FILESYSTEM = "filesystem"       # Écriture fichier
    DATABASE = "database"           # Écriture DB
    NETWORK_INTERNAL = "network_internal"  # API interne
    NETWORK_EXTERNAL = "network_external"  # API externe, email
    DANGEROUS_TOOL = "dangerous"    # execute_command, drop_table, etc.


# Patterns de détection automatique de classification
_SECRET_PATTERNS = [
    re.compile(r"\b(sk-|pk-|Bearer\s)[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),  # GitHub PAT
    re.compile(r"\b-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    re.compile(r"\b(api[_-]?key|password|secret|token)\s*[:=]\s*['\"]?[\w\-]{16,}['\"]?", re.I),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]

_PII_PATTERNS = [
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
    re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),  # Credit card
]


@dataclass
class TaintLabel:
    """Label de taint pour une donnée."""
    level: TaintLevel
    source: str = "unknown"  # d'où vient la donnée
    tags: Set[str] = field(default_factory=set)
    propagated_from: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.name,
            "source": self.source,
            "tags": list(self.tags),
            "propagated_from": self.propagated_from,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaintLabel":
        return cls(
            level=TaintLevel[data.get("level", "PUBLIC")],
            source=data.get("source", "unknown"),
            tags=set(data.get("tags", [])),
            propagated_from=data.get("propagated_from", []),
        )


class TaintTracker:
    """
    Traque la classification des données dans une session.
    
    Usage:
        tracker = TaintTracker()
        
        # Marque les données entrantes
        tracker.label("user_input", user_text, TaintLevel.UNTRUSTED, "web_form")
        tracker.label("api_key", api_key, TaintLevel.SECRET, "env_var")
        
        # Combine les labels quand des données sont mélangées
        combined = tracker.combine(["user_input", "api_key"])
        
        # Vérifie si un flux est autorisé
        violation = tracker.check_sink(combined, SinkType.NETWORK_EXTERNAL)
        if violation:
            raise SecurityException(f"Taint violation: {violation}")
    """

    # Règles de flux interdits par défaut
    DEFAULT_DENY_RULES = [
        # (source_level_min, sink_type, reason)
        (TaintLevel.SECRET, SinkType.NETWORK_EXTERNAL, "SECRET data cannot be sent to external networks"),
        (TaintLevel.SECRET, SinkType.DANGEROUS_TOOL, "SECRET data cannot be used in dangerous tools"),
        (TaintLevel.MALICIOUS, SinkType.INTERNAL, "MALICIOUS data blocked"),
        (TaintLevel.MALICIOUS, SinkType.FILESYSTEM, "MALICIOUS data blocked"),
        (TaintLevel.MALICIOUS, SinkType.DATABASE, "MALICIOUS data blocked"),
        (TaintLevel.UNTRUSTED, SinkType.DANGEROUS_TOOL, "UNTRUSTED data cannot be used in dangerous tools"),
    ]

    DEFAULT_REVIEW_RULES = [
        (TaintLevel.CONFIDENTIAL, SinkType.NETWORK_EXTERNAL, "CONFIDENTIAL data to external network requires approval"),
        (TaintLevel.CONFIDENTIAL, SinkType.FILESYSTEM, "CONFIDENTIAL data write requires approval"),
    ]

    def __init__(self):
        # id → TaintLabel
        self._labels: Dict[str, TaintLabel] = {}
        # id → valeur (pour re-analyse si besoin)
        self._values: Dict[str, Any] = {}

    def label(
        self,
        data_id: str,
        value: Any,
        level: Optional[TaintLevel] = None,
        source: str = "unknown",
        tags: Optional[Set[str]] = None,
    ) -> TaintLabel:
        """
        Attribue un label de taint à une donnée.
        Si level n'est pas fourni, auto-détecte.
        """
        if level is None:
            level = self._auto_classify(value)

        label = TaintLabel(
            level=level,
            source=source,
            tags=tags or set(),
        )
        self._labels[data_id] = label
        self._values[data_id] = value
        return label

    def _auto_classify(self, value: Any) -> TaintLevel:
        """Auto-classifie une valeur en analysant son contenu."""
        text = self._to_text(value)
        if not text:
            return TaintLevel.PUBLIC

        # Vérifie SECRET en premier (priorité)
        for pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                return TaintLevel.SECRET

        # Puis PII / CONFIDENTIAL
        for pattern in _PII_PATTERNS:
            if pattern.search(text):
                return TaintLevel.CONFIDENTIAL

        return TaintLevel.INTERNAL

    @staticmethod
    def _to_text(value: Any) -> str:
        """Convertit une valeur en texte pour analyse."""
        if isinstance(value, str):
            return value
        if isinstance(value, (dict, list)):
            try:
                return json.dumps(value, default=str)
            except Exception:
                return str(value)
        return str(value)

    def get_label(self, data_id: str) -> Optional[TaintLabel]:
        return self._labels.get(data_id)

    def combine(
        self,
        data_ids: List[str],
        new_id: Optional[str] = None,
    ) -> TaintLabel:
        """
        Combine plusieurs labels (ex: quand un LLM reçoit plusieurs inputs).
        Le résultat prend le niveau MAX (le plus dangereux).
        """
        if not data_ids:
            label = TaintLabel(TaintLevel.PUBLIC, "empty")
            if new_id:
                self._labels[new_id] = label
            return label

        max_level = TaintLevel.PUBLIC
        sources = []
        all_tags: Set[str] = set()
        propagated = []

        for did in data_ids:
            lbl = self._labels.get(did)
            if lbl:
                if lbl.level > max_level:
                    max_level = lbl.level
                sources.append(lbl.source)
                all_tags.update(lbl.tags)
                propagated.append(did)

        combined = TaintLabel(
            level=max_level,
            source="+".join(sources[:3]),  # max 3 sources dans le nom
            tags=all_tags,
            propagated_from=propagated,
        )

        if new_id:
            self._labels[new_id] = combined

        return combined

    def check_sink(
        self,
        label: TaintLabel,
        sink: SinkType,
    ) -> Optional[str]:
        """
        Vérifie si un flux label → sink est autorisé.
        
        Retourne:
            None si autorisé
            str avec raison si DENY
            "REVIEW:" + raison si approbation requise
        """
        # MALICIOUS → toujours bloqué
        if label.level == TaintLevel.MALICIOUS:
            return f"MALICIOUS data (from {label.source}) blocked at {sink.value}"

        # Check DENY rules
        for min_level, rule_sink, reason in self.DEFAULT_DENY_RULES:
            if label.level >= min_level and sink == rule_sink:
                return f"DENY: {reason} (source: {label.source})"

        # Check REVIEW rules
        for min_level, rule_sink, reason in self.DEFAULT_REVIEW_RULES:
            if label.level >= min_level and sink == rule_sink:
                return f"REVIEW: {reason} (source: {label.source})"

        return None

    def mark_malicious(self, data_id: str, reason: str = "injection_detected"):
        """Marque une donnée comme MALICIOUS (après détection d'injection)."""
        if data_id in self._labels:
            self._labels[data_id].level = TaintLevel.MALICIOUS
            self._labels[data_id].tags.add(reason)
        else:
            self.label(data_id, None, TaintLevel.MALICIOUS, reason, {reason})

    def get_report(self) -> Dict[str, Any]:
        """Résumé des labels actifs dans la session."""
        by_level: Dict[str, int] = {}
        for lbl in self._labels.values():
            by_level[lbl.level.name] = by_level.get(lbl.level.name, 0) + 1
        return {
            "total_tracked": len(self._labels),
            "by_level": by_level,
            "secrets_tracked": sum(1 for l in self._labels.values() if l.level == TaintLevel.SECRET),
            "malicious_detected": sum(1 for l in self._labels.values() if l.level == TaintLevel.MALICIOUS),
        }
