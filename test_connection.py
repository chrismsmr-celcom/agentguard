"""
Test rapide — vérifie que ton agent peut parler au collector Render.
"""
import os
import requests

COLLECTOR = os.environ.get("AGENTGUARD_COLLECTOR_URL", "https://agentguard-aqal.onrender.com")

print(f"🔗 Test de connexion vers: {COLLECTOR}")
print("-" * 50)

# Test 1: Health check
print("
[1/3] Health check (/api/metrics)...")
try:
    r = requests.get(f"{COLLECTOR}/api/metrics", timeout=15)
    print(f"   Status: {r.status_code}")
    print(f"   Body: {r.text[:200]}")
except Exception as e:
    print(f"   ❌ ÉCHEC: {e}")

# Test 2: Envoi d'une span factice
print("
[2/3] Envoi d'une span test...")
try:
    r = requests.post(
        f"{COLLECTOR}/span",
        json={
            "trace_id": "test-123",
            "span_id": "span-456",
            "span_type": "llm_call",
            "timestamp": 1234567890,
            "latency_ms": 100,
            "input_data": {"prompt": "hello"},
            "output_data": {"response": "world"},
            "security_checks": [
                {"check_name": "injection", "passed": True, "risk_level": "low", "details": "ok", "metadata": {}}
            ],
            "blocked": False,
            "block_reason": None,
            "cost_usd": 0.001
        },
        timeout=15,
        headers={"Content-Type": "application/json"}
    )
    print(f"   Status: {r.status_code}")
    print(f"   ✅ Span reçue!" if r.status_code == 201 else f"   ⚠️ Code inattendu")
except Exception as e:
    print(f"   ❌ ÉCHEC: {e}")

# Test 3: Vérification
print("
[3/3] Vérification dans la DB...")
try:
    r = requests.get(f"{COLLECTOR}/api/traces", timeout=15)
    data = r.json()
    print(f"   Traces trouvées: {len(data)}")
    if data:
        print(f"   ✅ La span est stockée!")
    else:
        print(f"   ⚠️ Aucune trace (DB vide ou span non stockée)")
except Exception as e:
    print(f"   ❌ ÉCHEC: {e}")

print("
" + "-" * 50)
print(f"👉 Ouvre ton dashboard: {COLLECTOR}")
