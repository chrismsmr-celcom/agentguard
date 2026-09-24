# --- DASHBOARD ---------------------------------------------------------------
# The dashboard markup (HTML + CSS + JS) lives in
# collector/templates/dashboard.html. It used to be a single 130 KB string
# literal in this module (issue #4). It is now loaded from disk once and
# exposed as DASHBOARD_HTML so existing imports keep working unchanged.

import os

_TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "templates",
    "dashboard.html",
)


def _load_dashboard_html():
    with open(_TEMPLATE_PATH, "r", encoding="utf-8") as fh:
        return fh.read()


DASHBOARD_HTML = _load_dashboard_html()
