"""
Garde-fou d'integrite des templates - filet de securite AVANT decoupage.

Contexte (issue #4) : collector/auth.py (128 Ko), collector/dashboard.py
(130 Ko) et collector/api.py (74 Ko) sont des monolithes. Avant de les
decouper, on fige ici les invariants observables afin que chaque extraction
incrementale soit verifiable.

Ce test PASSE sur le monolithe actuel et DOIT continuer a passer apres
chaque extraction. Il complete tests/test_dashboard_wiring.py (qui ne
couvre que les handlers onclick du dashboard).

NOTE : ces assertions portent sur le CONTENU, pas sur l'emplacement. Si un
bloc est extrait vers collector/templates/*.html, il faudra mettre a jour
l'import dans ce fichier - c'est volontaire : cela force a traiter le
refactor explicitement plutot qu'a le subir.
"""

import re

import pytest


# ---------------------------------------------------------------------------
# Imports des artefacts sous test
# ---------------------------------------------------------------------------

try:
    from collector.dashboard import DASHBOARD_HTML
except ImportError as exc:  # pragma: no cover
    pytest.skip(f"collector.dashboard indisponible: {exc}", allow_module_level=True)


AUTH_HTML_NAMES = ("SUPABASE_LOGIN_HTML", "LOGIN_HTML", "SIGNUP_HTML")


def _import_auth_html():
    """Retourne un dict {nom: contenu} des blocs HTML de auth.py."""
    import collector.auth as auth_mod

    return {name: getattr(auth_mod, name, None) for name in AUTH_HTML_NAMES}


AUTH_HTML = _import_auth_html()


# ---------------------------------------------------------------------------
# 1. Blocs HTML inline de auth.py
# ---------------------------------------------------------------------------

AUTH_HTML_MARKERS = {
    "SUPABASE_LOGIN_HTML": [
        "<!DOCTYPE html>",
        "supabase.createClient",
        "signInWithOtp",
        "signInWithOAuth",
        "btn-google",
        "btn-github",
        "/api/auth/supabase-session",
        "{{ supabase_url }}",
        "{{ supabase_anon_key }}",
    ],
    "LOGIN_HTML": [
        "<!DOCTYPE html>",
        'action="/login"',
        'name="email"',
        "switchTab",
        "{% if error %}",
        "{% if success %}",
        "/signup",
    ],
    "SIGNUP_HTML": [
        "<!DOCTYPE html>",
        'action="/signup"',
        'name="email"',
        'name="name"',
        'name="company"',
        "{% if error %}",
        "/login",
    ],
}


@pytest.mark.parametrize("block_name", sorted(AUTH_HTML_MARKERS))
def test_auth_html_block_exists_and_is_non_empty(block_name):
    """Chaque bloc HTML de auth.py doit exister et ne pas etre vide."""
    content = AUTH_HTML.get(block_name)
    assert content is not None, (
        f"{block_name} introuvable dans collector.auth - "
        "a-t-il ete extrait vers un template ? Mettre a jour cet import."
    )
    assert isinstance(content, str), f"{block_name} doit etre une str"
    assert len(content.strip()) > 500, (
        f"{block_name} semble tronque ({len(content)} octets)"
    )


@pytest.mark.parametrize("block_name", sorted(AUTH_HTML_MARKERS))
def test_auth_html_block_contains_markers(block_name):
    """Chaque bloc HTML doit contenir ses marqueurs structurels."""
    content = AUTH_HTML.get(block_name) or ""
    missing = [m for m in AUTH_HTML_MARKERS[block_name] if m not in content]
    assert not missing, f"{block_name} : marqueurs manquants {missing}"


def test_auth_html_blocks_are_distinct():
    """Les 3 blocs doivent etre distincts (pas de copier-coller accidentel)."""
    present = {k: v for k, v in AUTH_HTML.items() if v}
    values = list(present.values())
    assert len(values) == len(set(values)), (
        "Deux blocs HTML de auth.py sont identiques - duplication suspecte"
    )


def test_auth_html_blocks_are_balanced_html():
    """Chaque bloc doit etre un document HTML complet et equilibre."""
    for name, content in AUTH_HTML.items():
        if not content:
            continue
        assert content.count("<html") == content.count("</html>"), (
            f"{name} : balises <html> desequilibrees"
        )
        assert content.count("<body") == content.count("</body>"), (
            f"{name} : balises <body> desequilibrees"
        )
        assert content.count("<head") == content.count("</head>"), (
            f"{name} : balises <head> desequilibrees"
        )


# ---------------------------------------------------------------------------
# 2. Marqueurs structurels de DASHBOARD_HTML
# ---------------------------------------------------------------------------

DASHBOARD_MARKERS = [
    'id="approvalsPanel"',
    'id="agentsPanel"',
    'id="connectAgentModal"',
    'id="apiKeyModal"',
    'id="helpModal"',
    'id="btnApprovals"',
    'id="btnAgents"',
    'id="approvalsBadge"',
    'id="agentsBadge"',
    'id="view-overview"',
    'id="view-health"',
    'id="view-tracing"',
    'id="view-audit"',
    "/api/approvals?status=",
    "/api/agents",
    "/api/metrics",
    "/api/traces",
    "/api/keys",
    "resolveApproval(",
    "toggleAgent(",
    "openApprovalsPanel(",
    "openAgentsPanel(",
    "openConnectAgentModal(",
    "refreshAll(",
]


@pytest.mark.parametrize("marker", DASHBOARD_MARKERS)
def test_dashboard_html_contains_marker(marker):
    """DASHBOARD_HTML doit contenir chaque marqueur structurel."""
    assert marker in DASHBOARD_HTML, f"DASHBOARD_HTML : marqueur manquant {marker!r}"


def test_dashboard_html_is_non_empty_and_balanced():
    """DASHBOARD_HTML doit etre un document HTML complet."""
    assert len(DASHBOARD_HTML) > 50_000, (
        f"DASHBOARD_HTML semble tronque ({len(DASHBOARD_HTML)} octets)"
    )
    assert DASHBOARD_HTML.count("<html") == DASHBOARD_HTML.count("</html>")
    assert DASHBOARD_HTML.count("<body") == DASHBOARD_HTML.count("</body>")
    assert DASHBOARD_HTML.count("<script") == DASHBOARD_HTML.count("</script>")


def test_dashboard_html_has_no_unresolved_jinja():
    """DASHBOARD_HTML est servi tel quel : pas de balises Jinja de controle."""
    for token in ("{% if", "{% endif", "{% for", "{% endfor"):
        assert token not in DASHBOARD_HTML, (
            f"DASHBOARD_HTML contient du Jinja non resolu : {token!r}"
        )


# ---------------------------------------------------------------------------
# 3. Surface publique de auth.py
# ---------------------------------------------------------------------------

AUTH_PUBLIC_SYMBOLS = [
    "auth_bp",
    "require_auth",
    "require_human_auth",
    "require_role",
    "require_permission",
    "resolve_org_id",
    "resolve_full_identity",
    "authorize_resource_access",
    "safe_compare",
    "hash_key",
]


@pytest.mark.parametrize("symbol", AUTH_PUBLIC_SYMBOLS)
def test_auth_public_symbol_exists(symbol):
    """auth.py doit continuer d'exposer ses symboles publics."""
    import collector.auth as auth_mod

    assert hasattr(auth_mod, symbol), (
        f"collector.auth.{symbol} manquant - le decoupage a casse la surface publique"
    )


def test_auth_blueprint_is_registered_with_expected_routes():
    """Le Blueprint auth doit declarer au moins une route."""
    import collector.auth as auth_mod

    bp = auth_mod.auth_bp
    assert bp.name == "auth"
    assert len(bp.deferred_functions) > 0, "auth_bp n'a aucune route enregistree"


# ---------------------------------------------------------------------------
# 4. Contrat de module de dashboard.py
# ---------------------------------------------------------------------------


def test_dashboard_module_exports_single_html_constant():
    """dashboard.py doit exposer DASHBOARD_HTML comme unique artefact HTML."""
    import collector.dashboard as dash_mod

    assert hasattr(dash_mod, "DASHBOARD_HTML")
    big_html_attrs = [
        name
        for name in dir(dash_mod)
        if name.isupper()
        and isinstance(getattr(dash_mod, name), str)
        and len(getattr(dash_mod, name)) > 10_000
    ]
    assert big_html_attrs == ["DASHBOARD_HTML"], (
        f"dashboard.py expose plusieurs gros blocs HTML : {big_html_attrs}"
    )


def test_dashboard_html_has_no_duplicate_ids():
    """Aucun id HTML ne doit etre duplique dans DASHBOARD_HTML."""
    ids = re.findall(r'(?<![-\w])id="([^"]+)"', DASHBOARD_HTML)
    duplicates = {i for i in ids if ids.count(i) > 1}
    assert not duplicates, f"IDs HTML dupliques dans DASHBOARD_HTML : {duplicates}"
