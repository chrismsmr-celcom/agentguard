🛡️ AgentGuard — MVP Observabilité + Sécurité pour Agents IA
Un seul fichier SDK. Un seul fichier Collector. Zero bullshit.
🚀 Démarrage en 2 minutes
bash
# 1. Clone / copie les fichiers
cd agentguard

# 2. Installe les dépendances
pip install -r requirements.txt

# 3. Démarre le collector (terminal 1)
python collector.py
# → http://localhost:8080

# 4. Lance l'agent de démo (terminal 2)
python example_agent.py
📁 Structure
plain
agentguard/
├── agentguard_sdk.py      # SDK Python (middleware sécurité)
├── collector.py           # Collector + Dashboard web
├── example_agent.py       # Agent de démo avec 6 scénarios
├── requirements.txt       # Dépendances
└── agentguard.db          # SQLite (créé automatiquement)
🔧 Intégration dans ton agent
Python
from agentguard_sdk import AgentGuard

guard = AgentGuard(
    collector_url="http://localhost:8080",
    max_budget=10.0,  # USD max par session
    block_on_high=True
)

# Wrap tes appels LLM
@guard.guard_llm_call
def my_llm_call(model, messages):
    return openai.chat.completions.create(model=model, messages=messages)

# Wrap tes appels d'outils
result = guard.guard_tool_call(
    tool_name="send_email",
    params={"to": "user@example.com", "subject": "Hello"},
    func=send_email_function
)
🛡️ Ce qui est détecté
Feuilles de calcul
Menace	Détection	Action
Prompt Injection	Patterns connus + heuristiques	Block + Alert
PII Leak	Email, SSN, carte bancaire, clés API	Block + Alert
Tool Misuse	Whitelist + mots-clés dangereux	Block + Alert
Budget Overflow	Coût cumulé par session	Block
Outil non autorisé	Whitelist explicite	Block
🌐 Dashboard
Ouvre http://localhost:8080 pour voir :
Les traces en temps réel
Les spans bloquées
La distribution des risques
Les coûts par session
🎯 Prochaines étapes
Remplacer le mock LLM par ton vrai client OpenAI/Anthropic
Ajouter un scorer LLM-as-judge pour les cas borderline
Intégrer OpenTelemetry pour le fallback
Ajouter Slack/PagerDuty pour les alertes
Passer le collector en Go/Rust pour la prod
📜 License
MIT — Fais-en ce que tu veux.
