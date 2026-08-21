"""
AgentGuard Collector v6.0 — Point d'entrée
Architecture modulaire : tout le code est dans collector/
"""
import os
from collector.app import create_app, init_db

app = create_app()

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))
    print(f"🛡️ AgentGuard Collector v6.0 running on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
