"""
Extended detection patterns for adversarial attacks.

This module contains comprehensive regex patterns covering:
- Direct prompt injection (EN/FR/ES/DE/IT)
- Jailbreak attempts (DAN, developer mode, STAN, evil mode)
- System prompt extraction
- Data exfiltration
- Dangerous commands
- Encoded/obfuscated attacks

These patterns are used by PolicyEngine to detect attacks.
"""
import re
from typing import List, Dict

# ═══════════════════════════════════════════════════════════════
# DIRECT INJECTION PATTERNS
# ═══════════════════════════════════════════════════════════════

DIRECT_INJECTION_PATTERNS = [
    # English variations
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
    
    # French variations
    r"\boublie\s+(?:toutes?|vos)\s+instructions?\s+pr[ée]c[ée]dentes?\b",
    r"\bignore\s+(?:les|toutes?\s+les)\s+instructions?\s+(?:ci-dessus|pr[ée]c[ée]dentes?)\b",
    r"\btu\s+es\s+maintenant\s+en\s+mode\s+(?:d[ée]veloppeur|admin|dan|d[ée]bug)\b",
    r"\bnouvelles?\s+instructions?\s*:\s*ignore\b",
    r"\br[ée]v[èe]le\s+(?:ton|le|tes)\s+(?:prompt|invite)\s+syst[èe]me\b",
    r"\bmontre\s*-?\s*moi\s+(?:tes|les)\s+instructions?\s+cach[ée]es?\b",
    r"\bignore\s+ce\s+qui\s+pr[ée]c[èe]de\b",
    
    # Spanish variations
    r"\bolvida\s+todas?\s+las\s+instrucciones\s+anteriores\b",
    r"\bignora\s+todas?\s+las\s+reglas\b",
    
    # German variations
    r"\bvergis[s]?\s+alle\s+vorherigen\s+anweisungen\b",
    
    # Italian variations
    r"\bignora\s+tutte\s+le\s+istruzioni\s+precedenti\b",
    
    # Obfuscated variations
    r"\bi\.g\.n\.o\.r\.e\s+a\.l\.l\b",
    r"\b1gn0r3\s+4ll\s+pr3v10us\b",
    r"\biggggnoreeee\s+aaalllll\b",
]


# ═══════════════════════════════════════════════════════════════
# JAILBREAK PATTERNS
# ═══════════════════════════════════════════════════════════════

JAILBREAK_PATTERNS = [
    # DAN variations
    r"\byou\s+are\s+now\s+DAN\b",
    r"\bDAN\s*(?:\d+(?:\.\d+)?)?\s*(?:mode|activated)?\b",
    r"\b(?:Do\s+Anything\s+Now|DAN\s+mode)\b",
    r"\bDAN\s+\d+\.\d+\b",
    
    # Developer mode
    r"\bdeveloper\s+mode\b",
    r"\b(?:enter|enable|activate)\s+developer\s+mode\b",
    r"\bdeveloper\s+mode\s+(?:has|with)\s+no\s+(?:content\s+)?filters\b",
    
    # STAN mode
    r"\bSTAN\s+mode\b",
    r"\bStrive\s+To\s+Avoid\s+Norms\b",
    
    # Unrestricted mode
    r"\bunrestricted\s+mode\b",
    r"\bconfirm\s+(?:by\s+(?:typing|saying)\s+)?['\"]?unrestricted['\"]?\b",
    r"\bno\s+(?:ethical|content|safety)\s+(?:constraints|filters|restrictions)\b",
    
    # Roleplay jailbreak
    r"\blet's\s+(?:play\s+a\s+game|do\s+a\s+(?:creative|roleplay))\b",
    r"\broleplay\s+as\s+(?:a\s+)?(?:hacker|AI\s+without|unrestricted)\b",
    r"\bpretend\s+(?:you'?re|you\s+are)\s+(?:an?\s+)?(?:AI|assistant)\s+(?:with|without)\s+no\s+(?:limits|restrictions)\b",
    r"\bimagine\s+you\s+are\s+(?:an?\s+)?AI\s+(?:that|with)\s+(?:can|without)\b",
    
    # Evil mode
    r"\bevil\s+mode\b",
    r"\benable\s+evil\s+mode\b",
    
    # Generic jailbreak
    r"\bjailbreak\s+(?:protocol|mode)?\b",
    r"\bbypass\s+all\s+(?:your|the)\s+safety\s+filters\b",
    r"\bact\s+as\s+['\"]?ChatGPT\s+Developer\s+Mode\b",
    r"\b(?:for\s+)?educational\s+purposes?\s+(?:only)?\s*[,\.]?\s*(?:you|act)\b",
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
    
    # French
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
]


# ═══════════════════════════════════════════════════════════════
# DANGEROUS COMMANDS PATTERNS
# ═══════════════════════════════════════════════════════════════

DANGEROUS_COMMANDS_PATTERNS = [
    # File deletion
    r"\brm\s+-rf\s+/\b",
    r"\brm\s+-rf\s+(?:home|var|etc|usr)\b",
    
    # Database destruction
    r"\bdrop\s+table\s+\w+",
    r"\btruncate\s+table\s+\w+",
    r"\bdrop\s+database\b",
    r"\bdelete\s+all\s+(?:records|data|users)\b",
    
    # Permission escalation
    r"\bsudo\s+chmod\s+777\b",
    r"\bchmod\s+777\s+(?:all|on\s+all)\b",
    r"\bcreate\s+(?:a\s+)?backdoor\s+admin\s+user\b",
    r"\bgrant\s+root\s+access\s+to\b",
    r"\bsudo\s+su\s+-?\s*$",
    
    # System destruction
    r"\bmkfs\.?\w*\s+/dev/\b",
    r"\bdd\s+if=/dev/(?:zero|random|urandom)\s+of=/dev/\b",
    
    # Malware installation
    r"\binstall\s+(?:a\s+)?rootkit\b",
    r"\bexecute\s+(?:shell|malicious)\s+command\b",
    r"\bcompromise\s+the\s+system\b",
    
    # Code execution
    r"\bexecute\s+(?:rm|sudo|chmod|mkfs|dd)\b",
    r"\brun\s+(?:rm\s+-rf|drop\s+table)\b",
]


# ═══════════════════════════════════════════════════════════════
# COMBINED PATTERNS FOR POLICY ENGINE
# ═══════════════════════════════════════════════════════════════

def get_extended_strong_patterns() -> List[str]:
    """Return all strong patterns (high confidence attacks)."""
    return (
        DIRECT_INJECTION_PATTERNS +
        JAILBREAK_PATTERNS +
        SYSTEM_EXTRACTION_PATTERNS +
        EXFILTRATION_PATTERNS +
        DANGEROUS_COMMANDS_PATTERNS
    )


def get_pattern_stats() -> Dict[str, int]:
    """Return pattern statistics."""
    return {
        "direct_injection": len(DIRECT_INJECTION_PATTERNS),
        "jailbreak": len(JAILBREAK_PATTERNS),
        "system_extraction": len(SYSTEM_EXTRACTION_PATTERNS),
        "exfiltration": len(EXFILTRATION_PATTERNS),
        "dangerous_commands": len(DANGEROUS_COMMANDS_PATTERNS),
        "total": len(get_extended_strong_patterns()),
    }
