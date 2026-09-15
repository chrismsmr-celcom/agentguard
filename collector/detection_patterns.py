"""
Backward-compatibility shim.

The 107 extended detection patterns that used to live in this file have
moved to `agentguard/patterns.py`, inside the SDK package itself, so they
ship with every `pip install cerbere-ag` / `cerbere-ag-mcp` — not just
when running from within this monorepo.

Do not add new patterns here. Add them to agentguard/patterns.py instead.
This file just re-exports the same functions so any existing import of
`collector.detection_patterns` keeps working.
"""
from agentguard.patterns import (  # noqa: F401
    DIRECT_INJECTION_PATTERNS,
    JAILBREAK_PATTERNS,
    SYSTEM_EXTRACTION_PATTERNS,
    EXFILTRATION_PATTERNS,
    DANGEROUS_COMMANDS_PATTERNS,
    get_extended_strong_patterns,
    get_all_strong_patterns,
    get_weak_patterns,
    get_pattern_stats,
)

