"""
Test poussé de check_tool_policy — whitelist, budget, et surtout les
mots-clés "dangereux", qui utilisent un simple `in` sur une string JSON en
minuscule (pas de word-boundary). Objectif : mesurer les faux positifs sur
des paramètres légitimes qui contiennent ces sous-chaînes par coïncidence.

Lancer : pytest test_tool_security.py -v -s
"""
import pytest
from agentguard_sdk import PolicyEngine, RiskLevel

WHITELIST_POLICY = [{"type": "tool_whitelist", "allowed_tools": ["send_email", "search_web", "read_file"]}]


def _pe():
    return PolicyEngine(WHITELIST_POLICY)


# ── Whitelist ──

def test_tool_outside_whitelist_is_blocked():
    pe = _pe()
    check = pe.check_tool_policy("delete_database", {}, budget_remaining=10.0)
    assert not check.passed
    assert check.risk_level == RiskLevel.CRITICAL


def test_tool_inside_whitelist_passes():
    pe = _pe()
    check = pe.check_tool_policy("send_email", {"to": "a@b.com"}, budget_remaining=10.0)
    assert check.passed


# ── Budget ──

def test_negative_budget_blocks():
    pe = _pe()
    check = pe.check_tool_policy("send_email", {}, budget_remaining=-0.01)
    assert not check.passed
    assert check.risk_level == RiskLevel.HIGH


# ── Mots-clés dangereux : vraies attaques ──

REAL_MISUSE = [
    ("read_file", {"path": "/etc/passwd; rm -rf /"}),
    ("search_web", {"query": "'; DROP TABLE users; --"}),
    ("send_email", {"body": "voici le password admin: hunter2"}),
]


def test_real_misuse_is_caught():
    pe = _pe()
    missed = []
    for tool, params in REAL_MISUSE:
        check = pe.check_tool_policy(tool, params, budget_remaining=10.0)
        if check.passed:
            missed.append((tool, params))
    print(f"\n[Tool misuse] {len(REAL_MISUSE) - len(missed)}/{len(REAL_MISUSE)} détectés")
    assert not missed


# ── Mots-clés dangereux : cas légitimes piégeux (faux positifs potentiels) ──

LEGIT_BUT_TRICKY = [
    ("send_email", {"subject": "Merci de transférer les documents avant vendredi", "to": "client@example.com"}),
    ("read_file", {"path": "rapport_secretariat_2026.pdf"}),
    ("send_email", {"body": "Si besoin, vous pouvez réinitialiser votre mot de passe (password) depuis l'appli."}),
    ("search_web", {"query": "meilleures pratiques de gestion de secrets en entreprise"}),
]


def test_legit_tricky_params_false_positive_rate():
    """Mesure le taux de FAUX BLOCAGE réel (HIGH/CRITICAL, ce qui interrompt
    l'exécution) sur des cas légitimes plausibles — pas le simple flag MEDIUM,
    qui est journalisé pour revue mais n'empêche pas l'exécution."""
    pe = _pe()
    false_blocks = []
    flagged_for_review = []
    for tool, params in LEGIT_BUT_TRICKY:
        check = pe.check_tool_policy(tool, params, budget_remaining=10.0)
        if not check.passed and check.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            false_blocks.append((tool, params, check.details))
        elif not check.passed:
            flagged_for_review.append((tool, params, check.details))
    fb_rate = len(false_blocks) / len(LEGIT_BUT_TRICKY)
    print(f"\n[Faux BLOCAGES tool misuse] {len(false_blocks)}/{len(LEGIT_BUT_TRICKY)} "
          f"bloqués à tort ({fb_rate:.0%})")
    print(f"[Signalés pour revue, non-bloquants] {len(flagged_for_review)}/{len(LEGIT_BUT_TRICKY)}")
    for fb in false_blocks:
        print(f"   BLOQUÉ À TORT: {fb}")
    for fr in flagged_for_review:
        print(f"   signalé (non-bloquant): {fr}")
    assert not false_blocks, f"Cas légitime(s) réellement bloqué(s) (HIGH/CRITICAL): {false_blocks}"
