"""
Garde-fou dashboard : chaque onclick="fn(...)" doit pointer vers une fonction réellement définie.
(Le bug du 19/09 : les boutons Approuver/Rejeter appelaient resolveApproval(), jamais définie.)
"""
import re

from collector.dashboard import DASHBOARD_HTML

BUILTINS = {"if", "event", "this", "stopPropagation", "preventDefault", "closest", "querySelector",
            "getElementById", "contains", "add", "remove", "toggle", "focus", "select", "click"}


def _defined_functions():
    names = set(re.findall(r"function\s+([A-Za-z_$][\w$]*)\s*\(", DASHBOARD_HTML))
    names |= set(re.findall(r"window\.([A-Za-z_$][\w$]*)\s*=\s*function", DASHBOARD_HTML))
    names |= set(re.findall(r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function|\()", DASHBOARD_HTML))
    return names


def _onclick_calls():
    calls = set()
    for value in re.findall(r"onclick=\\?\"([^\"]*)\\?\"", DASHBOARD_HTML):
        for name in re.findall(r"([A-Za-z_$][\w$]*)\s*\(", value):
            calls.add(name)
    return calls - BUILTINS


def test_every_onclick_handler_is_defined():
    missing = sorted(_onclick_calls() - _defined_functions())
    assert not missing, f"onclick pointe vers des fonctions inexistantes : {missing}"


def test_approval_and_agent_panels_are_present():
    for marker in ("id=\"approvalsPanel\"", "id=\"agentsPanel\"", "id=\"btnApprovals\"", "id=\"btnAgents\"",
                   "/api/approvals?status=", "/api/agents", "toggleAgent(", "resolveApproval("):
        assert marker in DASHBOARD_HTML, marker
    # plus de doublon "AI Agents" / "+ Connection", plus d'ancienne bannière jaune
    assert "approval-pill" not in DASHBOARD_HTML
    assert 'onclick="openConnectModal()"' not in DASHBOARD_HTML   # plus de bouton doublon "+ Connection"

