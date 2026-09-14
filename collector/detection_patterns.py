"""
Backward compatibility shim.
Core patterns have moved to the SDK: agentguard.patterns
"""
from agentguard.patterns import (
    DIRECT_INJECTION_PATTERNS,
    JAILBREAK_PATTERNS,
    SYSTEM_EXTRACTION_PATTERNS,
    EXFILTRATION_PATTERNS,
    DANGEROUS_COMMANDS_PATTERNS,
    get_extended_strong_patterns,
    get_pattern_stats
)

# Si get_pattern_stats n'existe pas dans le nouveau fichier, on le définit ici pour éviter les crashs
if 'get_pattern_stats' not in dir():
    def get_pattern_stats():
        return {
            "direct_injection": len(DIRECT_INJECTION_PATTERNS),
            "jailbreak": len(JAILBREAK_PATTERNS),
            "system_extraction": len(SYSTEM_EXTRACTION_PATTERNS),
            "exfiltration": len(EXFILTRATION_PATTERNS),
            "dangerous_commands": len(DANGEROUS_COMMANDS_PATTERNS),
            "total": len(get_extended_strong_patterns()),
        }
