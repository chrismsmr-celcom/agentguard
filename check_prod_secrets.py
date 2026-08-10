#!/usr/bin/env python3
"""
Vérifie l'hygiène des secrets sur ton VRAI déploiement Render — je ne peux
pas m'y connecter depuis mon environnement, donc lance ceci toi-même.

Usage :
    python scripts/check_prod_secrets.py https://agentguard-aqal.onrender.com
"""
import sys
import requests

def check(name, condition, detail=""):
    status = "✅" if condition else "❌"
    print(f"{status} {name}" + (f" — {detail}" if detail else ""))
    return condition

def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/check_prod_secrets.py <URL_DE_TON_COLLECTOR>")
        sys.exit(1)

    base = sys.argv[1].rstrip("/")
    print(f"Vérification de {base}\n{'='*50}")
    all_ok = True

    # 1. Le dashboard/API ne doit JAMAIS répondre sans clé
    r = requests.get(f"{base}/api/metrics", timeout=10)
    all_ok &= check("Dashboard/API protégés sans clé", r.status_code == 401,
                     f"status reçu: {r.status_code} (attendu 401)")

    # 2. L'ancien secret par défaut ne doit plus jamais marcher
    r = requests.get(f"{base}/api/key", params={"admin": "changeme"}, timeout=10)
    all_ok &= check("Secret admin par défaut 'changeme' rejeté", r.status_code in (403, 404),
                     f"status reçu: {r.status_code}")

    # 3. /api/key doit être désactivé (404) si tu n'as jamais eu besoin de le garder actif
    if r.status_code == 404:
        print("   ℹ️  /api/key est désactivé (AGENTGUARD_ADMIN_SECRET non configuré, "
              "ou tu n'en as plus besoin) — c'est la position la plus sûre si tu ne "
              "t'en sers pas.")

    # 4. Provisioning client doit exiger le secret admin
    r = requests.post(f"{base}/admin/customers", json={"org_name": "test-audit"}, timeout=10)
    all_ok &= check("Provisioning client protégé sans secret admin", r.status_code in (403, 404),
                     f"status reçu: {r.status_code}")

    # 5. CORS ne doit pas exposer les routes sensibles à n'importe quelle origine
    r = requests.options(f"{base}/api/metrics",
                          headers={"Origin": "https://evil-site.example",
                                   "Access-Control-Request-Method": "GET"}, timeout=10)
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    all_ok &= check("Routes API non ouvertes en CORS large (hors /span)", acao != "*",
                     f"Access-Control-Allow-Origin reçu: '{acao}' (seul /span doit être '*')")

    # 6. Cookie de session doit être httponly + secure (visible seulement via un vrai
    #    navigateur normalement, mais on vérifie les headers Set-Cookie si présents)
    r = requests.get(f"{base}/?key=cle-qui-nexiste-pas", timeout=10)
    set_cookie = r.headers.get("Set-Cookie", "")
    if set_cookie:
        all_ok &= check("Cookie marqué HttpOnly + Secure",
                         "HttpOnly" in set_cookie and "Secure" in set_cookie,
                         f"Set-Cookie: {set_cookie[:80]}...")

    print(f"\n{'='*50}")
    print("✅ Tout est en ordre." if all_ok else "❌ Au moins un point à corriger ci-dessus.")
    print("\nCe script vérifie ce qui est observable de l'extérieur. Vérifie EN PLUS,")
    print("directement dans les variables d'environnement Render :")
    print("  - AGENTGUARD_API_KEY est fixée explicitement (pas auto-générée — sinon")
    print("    elle change et invalide tes intégrations à chaque redéploiement)")
    print("  - AGENTGUARD_FLASK_SECRET est fixée explicitement (sinon les cookies de")
    print("    session de tes clients deviennent invalides à chaque redéploiement)")
    print("  - AGENTGUARD_ADMIN_SECRET est une vraie valeur aléatoire longue, pas un mot simple")
    print("  - DATABASE_URL n'est visible que par toi (jamais loggée en clair)")

if __name__ == "__main__":
    main()
