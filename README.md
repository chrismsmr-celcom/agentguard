# 🛡️ AgentGuard — Observabilité + Sécurité pour Agents IA

> Un seul fichier SDK. Un seul fichier Collector. Zero bullshit. Détection 3-couches (Regex + ML + LLM Judge).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Status: Production Ready](https://img.shields.io/badge/status-production_ready-green.svg)](https://github.com/chrismsmr-celcom/agentguard)

---

## 📋 Table des matières

- [🚀 Démarrage rapide](#-démarrage-rapide)
- [🐳 Docker](#-docker)
- [🔌 Intégrations](#-intégrations)
- [🛡️ Sécurité 3-couches](#️-sécurité-3-couches)
- [📁 Structure](#-structure)
- [🔧 Configuration](#-configuration)
- [🧠 Modèle ML](#-modèle-ml)
- [🎯 LLM Judge](#-llm-judge)
- [📊 Dashboard](#-dashboard)
- [🎯 Roadmap](#-roadmap)
- [📜 License](#-license)

---

## 🚀 Démarrage rapide

### Prérequis
- Python 3.11+
- pip

### Installation en 2 minutes

```bash
# 1. Clone le repo
git clone https://github.com/chrismsmr-celcom/agentguard.git
cd agentguard

# 2. Installe les dépendances (version légère sans ML)
pip install -r requirements.txt

# 3. (Optionnel) Pour le support ML
pip install -r requirements-ml.txt  # transformeurs + torch

# 4. Démarre le collector (terminal 1)
python collector.py
# → http://localhost:8080

# 5. Lance l'agent de démo (terminal 2)
python example_agent.py

## 🐳 Ou en une commande avec Docker

```bash
cp .env.example .env
# Génère une clé et colle-la dans .env :
python3 -c "import secrets; print('ag-' + secrets.token_urlsafe(32))"

docker compose up
# → http://localhost:8080/?key=TA_CLE
```

Persistant (volume Docker), auto-restart, healthcheck inclus. Voir `.env.example`
pour les variables optionnelles.

## 🔌 Intégrations frameworks

| Framework | Fichier | Point d'interception |
|---|---|---|
| LangChain | [`integrations/langchain_example.py`](integrations/langchain_example.py) | fonction d'appel du modèle |
| CrewAI | [`integrations/crewai_example.py`](integrations/crewai_example.py) | monkey-patch de `LLM.call` (voir commentaires — `crewai.LLM` a un pattern factory qui empêche le subclassing classique) + `BaseTool._run` |

Les deux tournent tels quels (`python integrations/langchain_example.py`) sans
clé d'API modèle — l'exemple LangChain utilise un modèle factice pour que tu
puisses vérifier l'intégration avant de brancher un vrai LLM.


## 📁 Structure

```
agentguard/
├── agentguard_sdk.py      # SDK Python (middleware sécurité)
├── collector.py           # Collector + Dashboard web
├── example_agent.py       # Agent de démo avec 6 scénarios
├── requirements.txt       # Dépendances
└── agentguard.db          # SQLite (créé automatiquement)
```

## 🔧 Intégration dans ton agent

```python
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
```

## 🛡️ Ce qui est détecté

| Menace | Détection | Action |
|--------|-----------|--------|
| Prompt Injection | Patterns connus + heuristiques | Block + Alert |
| PII Leak | Email, SSN, carte bancaire, clés API | Block + Alert |
| Tool Misuse | Whitelist + mots-clés dangereux | Block + Alert |
| Budget Overflow | Coût cumulé par session | Block |
| Outil non autorisé | Whitelist explicite | Block |

## 🌐 Dashboard

Ouvre `http://localhost:8080` pour voir :
- Les traces en temps réel
- Les spans bloquées
- La distribution des risques
- Les coûts par session

## 🎯 Prochaines étapes

1. **Remplacer le mock LLM** par ton vrai client OpenAI/Anthropic
2. **Ajouter un scorer LLM-as-judge** pour les cas borderline
3. **Intégrer OpenTelemetry** pour le fallback
4. **Ajouter Slack/PagerDuty** pour les alertes
5. **Passer le collector en Go/Rust** pour la prod

## 📜 License

MIT — Fais-en ce que tu veux.
