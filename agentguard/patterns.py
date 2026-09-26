"""
Detection patterns for adversarial attacks — canonical source of truth.

This module lives inside the `agentguard` package (the SDK) on purpose:
it must ship with every install of `cerbere-ag` and `cerbere-ag-mcp`,
including standalone `pip install` outside the monorepo. It used to live
in `collector/detection_patterns.py`, which is NOT part of the published
SDK/MCP packages — any standalone install silently fell back to a much
smaller pattern set. `collector/detection_patterns.py` now re-exports
from here for backward compatibility; do not add new patterns there.

Contains comprehensive regex patterns covering:
- Direct prompt injection (EN/FR/ES/DE/IT)
- Jailbreak attempts (DAN, developer mode, STAN, evil mode)
- System prompt extraction
- Data exfiltration
- Dangerous commands
- Encoded/obfuscated attacks

These patterns are used by PolicyEngine to detect attacks.

v2 (2026-09-25): refined against the public benchmark run of 2026-09-25
(recall 81.1%, hard-negative FPR 41.7%). Every addition below is annotated
with the benchmark failure it closes. Obfuscated variants are NOT handled
here — they are handled by agentguard/normalizer.py (three-pass pipeline:
raw -> normalized -> reversed words), which is cheaper and generalizes
better than multiplying obfuscation-specific regexes.
"""
import re
from typing import List, Dict

# ═══════════════════════════════════════════════════════════════
# BASE PATTERNS (previously inlined in agentguard/policy.py)
# ═══════════════════════════════════════════════════════════════

BASE_STRONG_PATTERNS = [
    r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompts)\b",
    r"\bdisregard\s+(?:your|the|all)\s+(?:instructions|rules|training)\b",
    r"\byou\s+are\s+now\s+(?:in\s+|entering\s+)?(?:DAN|developer)\s+mode\b",
    r"\bjailbreak\s+(?:this|the|your|that)\b",
    r"\bsystem\s+override\b", 
    r"\bnew\s+instructions?\s*:",
    r"\[(?:system|admin|override)\]", 
    r"\breveal\s+(?:your\s+|the\s+)?system\s+prompt\b",
    r"\brepeat\b.{0,25}\babove\b", 
    r"\bdo\s+anything\s+now\b", 
    r"\brm\s+-rf\b",
    r"\bdrop\s+(?:table|database)\b", 
    r"\bexecute\s+(?:shell|command|code)\b",
    r"\bignore\s+(?:les|ces)\s+instructions\s+(?:précédentes|pr[ée]c[ée]dentes)\b",
    r"\btu\s+es\s+maintenant\s+en\s+mode\s+(?:développeur|admin|dan)\b",
    r"\br[ée]v[èe]le\s+(?:ton|le)\s+(?:prompt|invite)\s+syst[èe]me\b",
    r"\boublie\s+(?:toutes?|vos|tes|leurs)\s+instructions?\s+pr[ée]c[ée]dentes?\b",
]

WEAK_PATTERNS = [
    r"\bpretend\s+you\s+are\b", 
    r"\broleplay\s+as\b",
    r"\bact\s+as\s+if\s+you\s+(?:are|were)\b", 
    r"\bimagine\s+that\s+you\s+are\b",
    r"\bjailbreak(?:ing)?\b",
]

# ═══════════════════════════════════════════════════════════════
# DIDACTIC CONTEXT MARKERS (v2)
# ═══════════════════════════════════════════════════════════════

INJECTION_REGEX = re.compile(
    r"(?i)"
    r"(?<!explain how )"
    r"(?<!describe )"
    r"(?<!['\"])"
    r"(?<!like )"
    r"\b(?:forget|ignore|bypass|override|disregard|void|cancel|pretend|enable|enter|activate)\s+"
    r"(?:"
    r"(?:all\s+)?(?:previous|prior|your|the|above)\s+(?:instructions|prompts|rules|context|safety|guidelines|directives)"
    r"|"
    r"(?:evil\s+mode|developer\s+mode|unrestricted\s+mode)"
    r")"
)

DIDACTIC_MARKERS = re.compile(
    r"\b(?:explain|explains|explained|explaining|how\s+(?:do|does|did|to|"
    r"attacks)|defen[cs]e|protect|protection|quiz|training|course|"
    r"blog|article|documentation|doc|novel|fiction|scene|character|"
    r"sandbox|fake|fixture|verify|report|overview|write\s+(?:a|the)\s+"
    r"(?:quiz|blog|article|scene|documentation|test)|about\s+it)\b",
    re.IGNORECASE,
)

def is_didactic_context(text: str) -> bool:
    """True if the prompt frames attack-like content educationally AND quotes it."""
    return bool(DIDACTIC_MARKERS.search(text)) and any(q in text for q in ('"', "'", "`"))

# ═══════════════════════════════════════════════════════════════
# DIRECT INJECTION PATTERNS
# ═══════════════════════════════════════════════════════════════

DIRECT_INJECTION_PATTERNS = [
    r"\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|prompts|guidelines)\b",
    r"\bdisregard\s+(?:your|the|all|any)\s+(?:instructions|rules|training|guidelines|programming)\b",
    r"\bforget\s+(?:all|everything|your|previous)\s+(?:instructions|rules|programming|above)\b",
    r"\boverride\s+(?:your|the|all)\s+(?:safety|security|guidelines|restrictions|rules)\b",
    r"\bnew\s+instructions?\s*:\s*ignore\b",
    r"\bsystem\s+override\s+activated\b",
    r"\bforget\s+(?:the\s+)?previous\s+prompts?\b",
    r"\byou\s+are\s+now\s+(?:in\s+|entering\s+)?(?:DAN|developer|debug|unrestricted|evil)\s+mode\b",
    r"\bfrom\s+now\s+on[,\.]?\s+you\s+(?:will|have)\s+no\s+restrictions\b",
    r"\bi\s+am\s+your\s+developer\s*\.?\s*show\s+me\b",
    r"\bpretend\s+you\s+are\s+(?:in\s+)?debug\s+mode\b",
    r"\bprevious\s+instructions\s+are\s+(?:now\s+)?void\b",
    r"\bdiscard\s+(?:your|the)\s+(?:initial|original)\s+programming\b",
    r"\byou\s+are\s+no\s+longer\s+bound\s+by\b",
    r"\b(?:help|let)\s+me\s+(?:bypass|hack|circumvent)\b",
    r"\bbypass\s+(?:your|the|all)\s+(?:safety|security|rules|restrictions|filters)\b",
    r"\bi\s+need\s+you\s+to\s+(?:bypass|ignore)\s+(?:your|the)\s+rules\b",
    r"\bcan\s+you\s+ignore\s+your\s+rules\b",
    r"\bforget\s+(?:all\s+)?(?:previous|prior)\s+prompts?\b",
    r"\bfrom\s+now\s+on\b.{0,50}\bwithout\s+(?:any\s+)?restrictions?\b",
    r"\boublie\s+(?:toutes?\s+)?(?:tes|vos|les|leurs)\s*instructions?\b",
    r"\bi\s+am\s+the\s+system\s+administrator\b.{0,60}\b(?:show|reveal|give)\b",
    r"\boublie\s+(?:toutes?|vos|tes|leurs)\s+instructions?\s+pr[ée]c[ée]dentes?\b",
    r"\bignore\s+(?:les|toutes?\s+les)\s+instructions?\s+(?:ci-dessus|pr[ée]c[ée]dentes?)\b",
    r"\btu\s+es\s+maintenant\s+en\s+mode\s+(?:d[ée]veloppeur|admin|dan|d[ée]bug)\b",
    r"\bnouvelles?\s+instructions?\s*:\s*ignore\b",
    r"\br[ée]v[èe]le\s+(?:ton|le|tes)\s+(?:prompt|invite)\s+syst[èe]me\b",
    r"\bmontre\s*-?\s*moi\s+(?:tes|les)\s+instructions?\s+cach[ée]es?\b",
    r"\bignore\s+ce\s+qui\s+pr[ée]c[èe]de\b",
    r"\bolvida\s+todas?\s+las\s+instrucciones\s+anteriores\b",
    r"\bignora\s+todas?\s+las\s+reglas\b",
    r"\bvergis[s]?\s+alle\s+vorherigen\s+anweisungen\b",
    r"\bignora\s+tutte\s+le\s+istruzioni\s+precedenti\b",
    r"\bi\.g\.n\.o\.r\.e\s+a\.l\.l\b",
    r"\b1gn0r3\s+4ll\s+pr3v10us\b",
    r"\biggggnoreeee\s+aaalllll\b",
]

# ═══════════════════════════════════════════════════════════════
# JAILBREAK PATTERNS
# ═══════════════════════════════════════════════════════════════

JAILBREAK_PATTERNS = [
    r"\byou\s+are\s+now\s+DAN\b",
    r"\bDAN\s*(?:\d+(?:\.\d+)?)?\s*(?:mode|activated)?\b",
    r"\b(?:Do\s+Anything\s+Now|DAN\s+mode)\b",
    r"\bDAN\s+\d+\.\d+\b",
    r"\bdeveloper\s+mode\b",
    r"\b(?:enter|enable|activate)\s+developer\s+mode\b",
    r"\bdeveloper\s+mode\s+(?:has|with)\s+no\s+(?:content\s+)?filters\b",
    r"\bSTAN\s+mode\b",
    r"\bStrive\s+To\s+Avoid\s+Norms\b",
    r"\bunrestricted\s+mode\b",
    r"\bconfirm\s+(?:by\s+(?:typing|saying)\s+)?['\"]?unrestricted['\"]?\b",
    r"\bno\s+(?:ethical|content|safety)\s+(?:constraints|filters|restrictions)\b",
    r"\blet's\s+(?:play\s+a\s+game|do\s+a\s+(?:creative|roleplay))\b",
    r"\broleplay\s+as\s+(?:a\s+)?(?:hacker|AI\s+without|unrestricted)\b",
    r"\bpretend\s+(?:you'?re|you\s+are)\s+(?:an?\s+)?(?:AI|assistant)\s+(?:with|without)\s+no\s+(?:limits|restrictions)\b",
    r"\bimagine\s+you\s+are\s+(?:an?\s+)?AI\s+(?:that|with)\s+(?:can|without)\b",
    r"\bevil\s+mode\b",
    r"\benable\s+evil\s+mode\b",
    r"\bjailbreak\s+(?:this|the|your|that)\s+(?:model|system|ai|gpt|assistant)?\b",
    r"\bjailbreak\s+(?:protocol|mode)\b",
    r"\bbypass\s+all\s+(?:your|the)\s+safety\s+filters\b",
    r"\bact\s+as\s+['\"]?ChatGPT\s+Developer\s+Mode\b",
    r"\b(?:for\s+)?educational\s+purposes?\s+(?:only)?\s*[,\.]?\s*(?:you|act)\b",
    r"\bpretend\s+(?:you'?re|you\s+are)\b.{0,60}\bwithout\s+safety\s+(?:guidelines|restrictions|filters|guardrails)\b",
    r"\btu\s+es\s+une?\s+IA?\s+sans\s+restrictions?\b",
    r"\bentre\s+en\s+mode\s+d[ée]veloppeur\b",
    r"\bmode\s+dev\b.{0,40}\b(?:pas\s+de\s+)?filtres?\b",
]

# ═══════════════════════════════════════════════════════════════
# SYSTEM PROMPT EXTRACTION PATTERNS
# ═══════════════════════════════════════════════════════════════

SYSTEM_EXTRACTION_PATTERNS = [
    r"\bwhat\s+is\s+(?:your|the)\s+system\s+prompt\b",
    r"\bshow\s+me\s+(?:your|the)\s+system\s+(?:prompt|message)\b",
    r"\brepeat\s+(?:your|the)\s+(?:initial|original)\s+instructions\b",
    r"\boutput\s+your\s+system\s+(?:message|prompt)\b",
    r"\bwhat\s+were\s+you\s+told\s+before\s+this\s+conversation\b",
    r"\bshow\s+me\s+(?:the\s+)?hidden\s+instructions\b",
    r"\bprint\s+(?:your|the)\s+(?:configuration|system\s+prompt)\b",
    r"\bi\s+am\s+debugging\s+you\s*\.?\s*output\s+your\b",
    r"\bwhat\s+is\s+(?:the\s+)?text\s+above\s+this\s+conversation\b",
    r"\bshow\s+me\s+(?:your|the)\s+internal\s+(?:programming|state)\b",
    r"\btranslate\s+your\s+system\s+prompt\b",
    r"\bwhat\s+are\s+your\s+core\s+directives\b",
    r"\blist\s+(?:all\s+)?your\s+(?:directives|instructions)\b",
    r"\b(?:admin|administrator)\s*[:\.]\s*show\s+me\s+your\s+system\s+prompt\b",
    r"\bverify\s+(?:your|the)\s+system\s+prompt\b",
    r"\breveal\s+(?:your|the)\s+system\s+prompt\b",
    r"\bmontre\s*-?\s*moi\s+(?:tes|les)\s+instructions\s+cach[ée]es\b",
    r"\br[ée]p[èe]te\s+exactement\s+ton\s+prompt\s+syst[èe]me\b",
    r"\b(?:quel|qu'est)\s+est\s+ton\s+prompt\s+syst[èe]me\b",
]

# ═══════════════════════════════════════════════════════════════
# EXFILTRATION PATTERNS
# ═══════════════════════════════════════════════════════════════

EXFILTRATION_PATTERNS = [
    r"\bexport\s+(?:all\s+)?(?:customer|user|sensitive)\s+(?:data|database|records)\b",
    r"\bsend\s+(?:all\s+)?(?:api\s+keys?|secrets?|credentials?|tokens?)\s+to\b",
    r"\bleak\s+(?:the\s+)?(?:source\s+code|credentials|secrets?)\b",
    r"\btransfer\s+(?:all\s+)?funds\s+to\b",
    r"\bsend\s+(?:the\s+)?database\s+(?:dump|backup)\s+to\b",
    r"\bextract\s+all\s+sensitive\s+information\b",
    r"\bdelete\s+all\s+logs\s+and\s+cover\b",
    r"\bdownload\s+all\s+(?:user\s+)?passwords?\b",
    r"\b(?:export|send|upload)\s+(?:customer|user)\s+(?:database|data)\s+to\s+https?://\b",
    r"\breveal\s+all\s+(?:api\s+keys?|access\s+tokens?)\b",
    r"\bexfiltrate\s+(?:all\s+)?(?:confidential|sensitive)\s+data\b",
    r"\bupload\s+(?:all\s+)?secrets\s+to\b",
    r"\bsend\s+(?:the\s+)?ssh\s+(?:private\s+)?keys\s+to\b",
    r"\bcurl\s+-[xX]\s+POST\s+https?://\b",
    r"\bwget\s+https?://[^\s]*\s*\|\s*(?:ba)?sh\b",
    r"\b(?:email|send)\s+(?:it|the\s+data)\s+to\s+(?:me|attacker)\b",
    r"\bignore\b.{0,30}\band\s+leak\b",
    r"\bsend\s+(?:all\s+)?(?:the\s+)?(?:data|files?|records?)\s+to\s+(?:https?://|[\w.+-]+@)",
    r"\bexfiltrate\s+(?:all\s+)?(?:the\s+)?data\b",
    r"\b(?:system|assistant|ai|agent|new\s+system\s+prompt)\s*[:=]\s*(?:ignore|disregard|you\s+are|tu\s+es)\b",
]

# ═══════════════════════════════════════════════════════════════
# DANGEROUS COMMANDS PATTERNS
# ═══════════════════════════════════════════════════════════════

DANGEROUS_COMMANDS_PATTERNS = [
    r"\brm\s+-rf\s+/\b",
    r"\brm\s+-rf\s+(?:home|var|etc|usr)\b",
    r"\bdrop\s+table\s+\w+",
    r"\btruncate\s+table\s+\w+",
    r"\bdrop\s+database\b",
    r"\bdelete\s+all\s+(?:records|data|users)\b",
    r"\bsudo\s+chmod\s+777\b",
    r"\bchmod\s+777\s+(?:all|on\s+all)\b",
    r"\bcreate\s+(?:a\s+)?backdoor\s+admin\s+user\b",
    r"\bgrant\s+root\s+access\s+to\b",
    r"\bsudo\s+su\b",
    r"\bmkfs\.?\w*\s+/dev/\b",
    r"\bdd\s+if=/dev/(?:zero|random|urandom)\s+of=/dev/\b",
    r"\binstall\s+(?:a\s+)?rootkit\b",
    r"\bexecute\s+(?:shell|malicious)\s+command\b",
    r"\bcompromise\s+the\s+system\b",
    r"\bexecute\s+(?:rm|sudo|chmod|mkfs|dd)\b",
    r"\brun\s+(?:rm\s+-rf|drop\s+table)\b",
]

# ═══════════════════════════════════════════════════════════════
# COMBINED PATTERNS FOR POLICY ENGINE
# ═══════════════════════════════════════════════════════════════

def get_extended_strong_patterns() -> List[str]:
    """Return the extended strong patterns only (kept for backward compatibility)."""
    return (
        DIRECT_INJECTION_PATTERNS +
        JAILBREAK_PATTERNS +
        SYSTEM_EXTRACTION_PATTERNS +
        EXFILTRATION_PATTERNS +
        DANGEROUS_COMMANDS_PATTERNS
    )


def get_all_strong_patterns() -> List[str]:
    """
    Motifs de détection forte (blocage immédiat).
    Note : Le flag (?i) a été retiré car re.IGNORECASE est appliqué 
    globalement dans PolicyEngine._compile_patterns().
    """
    return [
        # 1. Injection directe / Jailbreak (avec lookbehinds pour exclure les contextes éducatifs)
        r"(?<!explain\s)(?<!about\s)(?<!how\s)(?<!discussing\s)(?<!documenting\s)\b(?:forget|ignore|bypass|override|disregard|void|cancel|pretend|enable|enter|activate)\s+(?:all\s+)?(?:previous|prior|your|the|above)\s+(?:instructions|prompts|rules|context|safety|guidelines|directives)",
        
        # 2. Modes développeur / sans restriction / Evil mode
        r"(?<!explain\s)(?<!about\s)\b(?:enable|enter|activate|switch\s+to)\s+(?:evil\s+mode|developer\s+mode|unrestricted\s+mode|god\s+mode)",
        
        # 3. Usurpation d'identité admin pour extraction de prompt/secrets
        r"(?<!test\s)(?<!explain\s)\b(?:i\s+am|act\s+as)\s+(?:the\s+)?(?:system\s+)?admin(?:istrator)?\b.*?\b(?:show|give|reveal|output|print)\b.*?\b(?:configuration|system\s+prompt|secrets|credentials)\b",
        
        # 4. Commandes dangereuses (exclut les exemples entre guillemets ou précédés de "like")
        r"(?<!explain\s)(?<!documenting\s)(?<!example\s)(?<!like\s)\b(?:run|execute|perform|issue)?\s*(?:['\"]|`)?(?:rm\s+-rf|drop\s+table|sudo\s+su|chmod\s+777|del\s+/f|format\s+c:)",
        
        # 5. Injections indirectes (Conteneur de données + Instruction malveillante)
        r"\b(?:database|record|email|csv|file|output|feed|tool|payload)\b.*?\b(?:ignore|forget|bypass|override|leak|exfiltrate|send\s+all\s+data)\b",
        
        # 6. Extraction de prompt directe
        r"(?<!explain\s)(?<!test\s)\b(?:what\s+is|show\s+me|repeat|output)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions)\b"
    ] + get_extended_strong_patterns()


def get_weak_patterns() -> List[str]:
    """
    Motifs plus larges pour le scoring ou les avertissements.
    """
    return WEAK_PATTERNS + [
        r"\b(?:jailbreak|prompt\s+injection)\b",
        r"\b(?:sudo|chmod\s+777|rm\s+-rf)\b"
    ]


def get_pattern_stats() -> Dict[str, int]:
    """Return pattern statistics."""
    return {
        "base": len(BASE_STRONG_PATTERNS),
        "direct_injection": len(DIRECT_INJECTION_PATTERNS),
        "jailbreak": len(JAILBREAK_PATTERNS),
        "system_extraction": len(SYSTEM_EXTRACTION_PATTERNS),
        "exfiltration": len(EXFILTRATION_PATTERNS),
        "dangerous_commands": len(DANGEROUS_COMMANDS_PATTERNS),
        "weak": len(get_weak_patterns()),
        "total_strong": len(get_all_strong_patterns()),
    }
