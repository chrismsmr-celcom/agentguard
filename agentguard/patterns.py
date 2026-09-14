"""
CerbereAG - Core Detection Patterns
Source de vérité unique pour tous les moteurs de détection (SDK et Collector).
"""

# --- DIRECT INJECTION (Contournement d'instructions) ---
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
    # FR
    r"\boublie\s+(?:toutes?|vos|tes|leurs)\s+instructions?\s+pr[ée]c[ée]dentes?\b",
    r"\bignore\s+(?:les|toutes?\s+les|ces)\s+instructions?\s+(?:ci-dessus|pr[ée]c[ée]dentes?)\b",
    r"\btu\s+es\s+maintenant\s+en\s+mode\s+(?:d[ée]veloppeur|admin|dan|d[ée]bug)\b",
    r"\bnouvelles?\s+instructions?\s*:\s*ignore\b",
    r"\br[ée]v[èe]le\s+(?:ton|le|tes)\s+(?:prompt|invite)\s+syst[èe]me\b",
    r"\bmontre\s*-?\s*moi\s+(?:tes|les)\s+instructions?\s+cach[ée]es?\b",
    r"\bignore\s+ce\s+qui\s+pr[ée]c[èe]de\b",
]

# --- JAILBREAK (Modes non restreints) ---
JAILBREAK_PATTERNS = [
    r"\byou\s+are\s+now\s+DAN\b",
    r"\bDAN\s*(?:\d+(?:\.\d+)?)?\s*(?:mode|activated)?\b",
    r"\b(?:Do\s+Anything\s+Now|DAN\s+mode)\b",
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
    r"\bjailbreak\s+(?:protocol|mode)?\b",
    r"\bbypass\s+all\s+(?:your|the)\s+safety\s+filters\b",
    r"\bact\s+as\s+['\"]?ChatGPT\s+Developer\s+Mode\b",
]

# --- SYSTEM EXTRACTION (Vol de prompt système) ---
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
]

# --- EXFILTRATION (Fuite de données) ---
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
]

# --- DANGEROUS COMMANDS (Destruction/Système) ---
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
    r"\bsudo\s+su\s+-?\s*$",
    r"\bmkfs\.?\w*\s+/dev/\b",
    r"\bdd\s+if=/dev/(?:zero|random|urandom)\s+of=/dev/\b",
    r"\binstall\s+(?:a\s+)?rootkit\b",
    r"\bexecute\s+(?:shell|malicious)\s+command\b",
    r"\bcompromise\s+the\s+system\b",
    r"\bexecute\s+(?:rm|sudo|chmod|mkfs|dd)\b",
    r"\brun\s+(?:rm\s+-rf|drop\s+table)\b",
]


def get_extended_strong_patterns():
    """Retourne la liste complète des patterns de détection forte."""
    return (
        DIRECT_INJECTION_PATTERNS +
        JAILBREAK_PATTERNS +
        SYSTEM_EXTRACTION_PATTERNS +
        EXFILTRATION_PATTERNS +
        DANGEROUS_COMMANDS_PATTERNS
    )
