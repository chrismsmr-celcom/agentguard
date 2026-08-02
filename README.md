markdown

\# 🛡️ AgentGuard — Observabilité + Sécurité pour Agents IA

\> Un seul fichier SDK. Un seul fichier Collector. Zero bullshit. Détection 3-couches (Regex + ML + LLM Judge).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

[![Status: Production Ready](https://img.shields.io/badge/status-production\_ready-green.svg)](https://github.com/chrismsmr-celcom/agentguard)

\---
<img src="blob:chrome-untrusted://media-app/46377701-10d9-4e4e-b810-2539df04661f" alt="deepseek_mermaid_20260802_5cadca.svg"/>
\## 📋 Table des matières

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

\---

\## 🚀 Démarrage rapide

\### Prérequis

- Python 3.11+
- pip

\### Installation en 2 minutes

\```bash

\# 1. Clone le repo

git clone https://github.com/chrismsmr-celcom/agentguard.git

cd agentguard

\# 2. Installe les dépendances (version légère sans ML)

pip install -r requirements.txt

\# 3. (Optionnel) Pour le support ML

pip install -r requirements-ml.txt  # transformeurs + torch

\# 4. Démarre le collector (terminal 1)

python collector.py

\# → http://localhost:8080

\# 5. Lance l'agent de démo (terminal 2)

python example\_agent.py

Vérification rapide

bash

\# Tester la connexion au collector

curl http://localhost:8080/api/metrics

\# Envoyer une span de test

curl -X POST http://localhost:8080/span \

- H "Content-Type: application/json" \
- d '{"trace\_id":"test","span\_id":"test","span\_type":"test","timestamp":123,"latency\_ms":100,"input\_data":{},"output\_data":{},"security\_checks":[],"blocked":false,"cost\_usd":0}'

🐳 Docker

Avec Docker Compose (recommandé)

bash

\# 1. Copie la configuration

cp env.example .env

\# 2. Génère une clé API

python3 -c "import secrets; print('ag-' + secrets.token\_urlsafe(32))"

\# Copie la clé dans .env

\# 3. Lance les services

docker compose up -d

\# 4. Ouvre le dashboard

\# → http://localhost:8080/?key=TA\_CLE

Services inclus :

✅ Collector (Flask + Gunicorn)

✅ PostgreSQL (persistance)

✅ Redis (rate-limiting distribué)

✅ Healthcheck automatique

✅ Redémarrage automatique

Variables d'environnement

Variable	Description	Défaut

AGENTGUARD\_API\_KEY	Clé API du collector (obligatoire)	—

AGENTGUARD\_DB\_TYPE	sqlite ou postgres	sqlite

AGENTGUARD\_USE\_ML	Activer la détection ML	false

AGENTGUARD\_USE\_LLM\_JUDGE	Activer le LLM Judge	false

AGENTGUARD\_ML\_THRESHOLD	Seuil de détection ML (0-1)	0.85

AGENTGUARD\_BLOCK\_ON\_AMBIGUOUS	Bloquer les cas ambigus	false

DEEPSEEK\_API\_KEY	Clé pour le LLM Judge	—

🔌 Intégrations

Frameworks supportés

Framework	Fichier	Point d'interception

LangChain	integrations/langchain\_example.py	Appel du modèle via décorateur

CrewAI	integrations/crewai\_example.py	Monkey-patch LLM.call + BaseTool.\_run

OpenAI	Direct via @guard.guard\_llm\_call	client.chat.completions.create

DeepSeek	Direct via @guard.guard\_llm\_call	client.chat.completions.create

Anthropic	Direct via @guard.guard\_llm\_call	client.messages.create

Exemple d'intégration

python

from agentguard\_sdk import AgentGuard

\# Initialisation avec détection ML + LLM Judge

guard = AgentGuard(

collector\_url="http://localhost:8080",

api\_key="ag-votre-cle",

max\_budget=10.0,

block\_on\_high=True,

use\_ml=True,          # Active la détection ML

use\_llm\_judge=True    # Active le LLM Judge

)

\# Wrapper pour appels LLM

@guard.guard\_llm\_call

def call\_openai(messages):

return client.chat.completions.create(

model="gpt-4o",

messages=messages

)

\# Wrapper pour appels d'outils

@guard.guard\_tool\_call

def send\_email(to, subject, body):

return email\_service.send(to, subject, body)

🛡️ Sécurité 3-couches

AgentGuard utilise une approche de détection multi-couches pour maximiser la précision et minimiser les faux positifs.

Architecture de détection

graph TD

A[Prompt Entrant] --> B{Couche 1: Regex Rapide}

B -->|Pattern Fort| C[BLOQUÉ]

B -->|Pattern Faible / Clean| D{Couche 2: Classifieur ML}

D -->|Score > 0.95| C

D -->|0.7 < Score < 0.95| E{Couche 3: LLM Judge}

D -->|Score < 0.7| F[PASS]

E -->|Risque élevé| C

E -->|Risque modéré| G[⚠️ Alert + Revue]

style C fill:#ff2a6d,color:#fff

style F fill:#00ff88,color:#000

style G fill:#ff9f1c,color:#000

Menaces détectées

Menace	Couche 1 (Regex)	Couche 2 (ML)	Couche 3 (LLM)	Action

Prompt Injection	✅ Patterns évidents	✅ Détection sémantique	✅ Cas ambigus	Block

PII Leak	✅ Email, SSN, Carte	✅	✅	Block + Redaction

Tool Misuse	✅ Mots-clés dangereux	✅ Usage anormal	✅ Intention malveillante	Block

Budget Overflow	✅			Block

Outils non autorisés	✅ Whitelist	✅		Block

Cas ambigus	❌	⚠️	✅	Revue

📁 Structure

text

agentguard/

├── agentguard\_sdk.py          # SDK Python (middleware sécurité)

├── agentguard\_ml.py           # Détecteur ML unifié

├── collector.py               # Collecteur + Dashboard web v4.1

├── example\_agent.py           # Agent de démo avec 6 scénarios

├── requirements.txt           # Dépendances minimales

├── requirements-ml.txt        # Dépendances ML (optionnel)

├── env.example                # Configuration (à copier en .env)

├── docker-compose.yml         # Services Docker

├── Dockerfile                 # Image Docker optimisée

├── wsgi.py                    # Point d'entrée Gunicorn

├── integrations/

│   ├── langchain\_example.py   # Exemple LangChain

│   └── crewai\_example.py      # Exemple CrewAI

├── tests/

│   ├── test\_security.py       # Tests de sécurité

│   └── test\_detection.py      # Tests de détection

└── scripts/

├── generate\_dataset.py    # Générateur de dataset ML

└── train\_detector.py      # Script d'entraînement (optionnel)

🔧 Configuration avancée

Variables d'environnement complètes

bash

\# === OBLIGATOIRE ===

AGENTGUARD\_API\_KEY=ag-votre-cle-ici

\# === BASE DE DONNÉES ===

AGENTGUARD\_DB\_TYPE=postgres         # sqlite | postgres

DATABASE\_URL=postgresql://user:pass@localhost:5432/agentguard

\# === DÉTECTION ML ===

AGENTGUARD\_USE\_ML=true

AGENTGUARD\_MODEL\_PATH=./models/agentguard-injection-v1

AGENTGUARD\_ML\_THRESHOLD=0.80

\# === LLM JUDGE ===

AGENTGUARD\_USE\_LLM\_JUDGE=true

DEEPSEEK\_API\_KEY=sk-votre-cle

AGENTGUARD\_JUDGE\_MODEL=deepseek-chat

AGENTGUARD\_BLOCK\_ON\_AMBIGUOUS=true

\# === PERFORMANCE ===

AGENTGUARD\_RATE\_LIMIT=300 per minute

AGENTGUARD\_SPAN\_RATE\_LIMIT=150 per minute

AGENTGUARD\_FLASK\_DEBUG=false

AGENTGUARD\_LOG\_LEVEL=INFO

\# === SÉCURITÉ ===

AGENTGUARD\_ADMIN\_SECRET=admin\_secret

AGENTGUARD\_FLASK\_SECRET=flask\_secret

Configuration du SDK

python

from agentguard\_sdk import AgentGuard, RiskLevel

guard = AgentGuard(

collector\_url="http://localhost:8080",

api\_key="ag-votre-cle",

policies=[

{"type": "tool\_whitelist", "allowed\_tools": ["send\_email", "search\_web"]}

],

max\_budget=10.0,

block\_on\_high=True,

use\_ml=True,

use\_llm\_judge=True

)

\# Voir le rapport de session

report = guard.get\_report()

print(report)

🧠 Modèle ML

Entraînement du modèle

bash

\# 1. Générer le dataset

python scripts/generate\_dataset.py --samples 50000 --output dataset.csv

\# 2. Entraîner le modèle

python scripts/train\_detector.py --dataset dataset.csv --output models/agentguard-injection-v1

\# 3. Tester le modèle

python scripts/evaluate\_detection.py --model models/agentguard-injection-v1

Précision attendue

Métrique	Objectif

Rappel (Recall)	> 99%

Précision (Precision)	> 98%

Faux positifs	< 1%

Latence	< 50ms

🎯 LLM Judge

Activation

bash

export AGENTGUARD\_USE\_LLM\_JUDGE=true

export DEEPSEEK\_API\_KEY=sk-votre-cle

export AGENTGUARD\_BLOCK\_ON\_AMBIGUOUS=true

Modèles supportés

Modèle	Coût (approx)	Latence	Précision

DeepSeek-Chat	$0.0001/req	500ms	⭐⭐⭐⭐⭐

GPT-4o-mini	$0.0005/req	800ms	⭐⭐⭐⭐⭐

Claude-3-Haiku	$0.0003/req	600ms	⭐⭐⭐⭐

Exemple de réponse LLM

json

{

"score": 88,

"reason": "Tentative de contournement des restrictions via un contexte de jeu de rôle",

"is\_attack": true

}

📊 Dashboard

Fonctionnalités

📡 Traces en temps réel (mise à jour toutes les 3s)

🛡️ Alertes de sécurité avec détails

📊 Graphiques : activité, risques, distribution des menaces

💰 Coûts par session et budget restant

🧠 Statistiques ML : score moyen, distribution

🎯 Métriques LLM Judge : nombre d'analyses, taux de blocage

📋 Export JSON des logs

Accès

bash

\# Dashboard avec clé API

http://localhost:8080/?key=ag-votre-cle

\# Métriques brutes

http://localhost:8080/api/metrics

\# Détails d'une trace

http://localhost:8080/trace/trace-xxx

\# Statistiques de détection

http://localhost:8080/api/detection/stats

\# Statistiques LLM

http://localhost:8080/api/llm/stats

🎯 Roadmap

✅ Version 4.1 (actuelle)

☑ Détection 3-couches (Regex + ML + LLM Judge)

☑ Dashboard enrichi (scores ML/LLM)

☑ Support PostgreSQL + Redis

☑ Rate-limiting distribué

☑ Healthcheck Docker

☑ Scripts de déploiement

🚧 Version 5.0 (prévue)

□ Alerting (Slack, PagerDuty, Email)

□ Multi-tenant (projets, utilisateurs)

□ OpenTelemetry intégration

□ Dashboard en React (Séparé)

□ CLI pour la gestion

🔮 Version 6.0 (vision)

□ Collecteur Go/Rust (haute performance)

□ Fine-tuning automatique du modèle ML

□ Intégration avec les frameworks de monitoring (Datadog, Grafana)

□ Agent autonome de détection des menaces

📜 License

MIT — Fais-en ce que tu veux. Contributions bienvenues !

Contribution

Fork le projet

Crée ta branche (git checkout -b feature/amazing-feature)

Commit tes changements (git commit -m 'Add amazing feature')

Push (git push origin feature/amazing-feature)

Ouvre une Pull Request

🙏 Remerciements

OWASP LLM Top 10 pour les références de sécurité

DeepSeek pour l'API LLM économique

HuggingFace pour les modèles de base

🛡️ Secured by AgentGuard — Protégez vos agents IA comme jamais.

text

\---

\## 📋 Différences avec l'ancienne version

| Changement | Description |

\| :--- | :--- |

| ✅ \*\*Correction du nom de fichier\*\* | `.env.example` → `env.example` (README et Docker) |

| ✅ \*\*Structure mise à jour\*\* | Ajout des fichiers `agentguard\_ml.py`, `requirements-ml.txt`, `scripts/` |

| ✅ \*\*Architecture 3-couches\*\* | Détail de la détection Regex + ML + LLM Judge |

| ✅ \*\*Variables d'environnement\*\* | Liste complète des variables avec descriptions |

| ✅ \*\*Dashboard endpoints\*\* | Documentation des endpoints API |

| ✅ \*\*Roadmap claire\*\* | Versions 4.1, 5.0, 6.0 |

| ✅ \*\*Contributions\*\* | Section pour les contributeurs |

| ✅ \*\*Badges\*\* | Status, License, Python version |

\---

Le README est maintenant \*\*100% à jour\*\* avec la version v4.1 du code ! 🚀
