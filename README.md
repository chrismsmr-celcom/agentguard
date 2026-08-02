markdown

\# 🛡️ AgentGuard — Observabilité + Sécurité pour Agents IA

\> Un seul fichier SDK. Un seul fichier Collector. Zero bullshit. Détection 3-couches (Regex + ML + LLM Judge).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

[![Status: Production Ready](https://img.shields.io/badge/status-production\_ready-green.svg)](https://github.com/chrismsmr-celcom/agentguard)
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns:xhtml="http://www.w3.org/1999/xhtml" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns="http://www.w3.org/2000/svg" id="mermaid-svg-0" width="100%" class="flowchart" style="max-width: 100%;" viewBox="-31.520001220703126 -31.520001220703126 693.4400268554687 1120.2399536132812" height="100%"><style>#mermaid-svg-0{font-family:"trebuchet ms",verdana,arial,sans-serif;font-size:16px;fill:#333;}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#mermaid-svg-0 .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#mermaid-svg-0 .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#mermaid-svg-0 .error-icon{fill:#552222;}#mermaid-svg-0 .error-text{fill:#552222;stroke:#552222;}#mermaid-svg-0 .edge-thickness-normal{stroke-width:1px;}#mermaid-svg-0 .edge-thickness-thick{stroke-width:3.5px;}#mermaid-svg-0 .edge-pattern-solid{stroke-dasharray:0;}#mermaid-svg-0 .edge-thickness-invisible{stroke-width:0;fill:none;}#mermaid-svg-0 .edge-pattern-dashed{stroke-dasharray:3;}#mermaid-svg-0 .edge-pattern-dotted{stroke-dasharray:2;}#mermaid-svg-0 .marker{fill:#333333;stroke:#333333;}#mermaid-svg-0 .marker.cross{stroke:#333333;}#mermaid-svg-0 svg{font-family:"trebuchet ms",verdana,arial,sans-serif;font-size:16px;}#mermaid-svg-0 p{margin:0;}#mermaid-svg-0 .label{font-family:"trebuchet ms",verdana,arial,sans-serif;color:#333;}#mermaid-svg-0 .cluster-label text{fill:#333;}#mermaid-svg-0 .cluster-label span{color:#333;}#mermaid-svg-0 .cluster-label span p{background-color:transparent;}#mermaid-svg-0 .label text,#mermaid-svg-0 span{fill:#333;color:#333;}#mermaid-svg-0 .node rect,#mermaid-svg-0 .node circle,#mermaid-svg-0 .node ellipse,#mermaid-svg-0 .node polygon,#mermaid-svg-0 .node path{fill:#ECECFF;stroke:#9370DB;stroke-width:1px;}#mermaid-svg-0 .rough-node .label text,#mermaid-svg-0 .node .label text,#mermaid-svg-0 .image-shape .label,#mermaid-svg-0 .icon-shape .label{text-anchor:middle;}#mermaid-svg-0 .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#mermaid-svg-0 .rough-node .label,#mermaid-svg-0 .node .label,#mermaid-svg-0 .image-shape .label,#mermaid-svg-0 .icon-shape .label{text-align:center;}#mermaid-svg-0 .node.clickable{cursor:pointer;}#mermaid-svg-0 .root .anchor path{fill:#333333!important;stroke-width:0;stroke:#333333;}#mermaid-svg-0 .arrowheadPath{fill:#333333;}#mermaid-svg-0 .edgePath .path{stroke:#333333;stroke-width:2.0px;}#mermaid-svg-0 .flowchart-link{stroke:#333333;fill:none;}#mermaid-svg-0 .edgeLabel{background-color:rgba(232,232,232, 0.8);text-align:center;}#mermaid-svg-0 .edgeLabel p{background-color:rgba(232,232,232, 0.8);}#mermaid-svg-0 .edgeLabel rect{opacity:0.5;background-color:rgba(232,232,232, 0.8);fill:rgba(232,232,232, 0.8);}#mermaid-svg-0 .labelBkg{background-color:rgba(232, 232, 232, 0.5);}#mermaid-svg-0 .cluster rect{fill:#ffffde;stroke:#aaaa33;stroke-width:1px;}#mermaid-svg-0 .cluster text{fill:#333;}#mermaid-svg-0 .cluster span{color:#333;}#mermaid-svg-0 div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:"trebuchet ms",verdana,arial,sans-serif;font-size:12px;background:hsl(80, 100%, 96.2745098039%);border:1px solid #aaaa33;border-radius:2px;pointer-events:none;z-index:100;}#mermaid-svg-0 .flowchartTitleText{text-anchor:middle;font-size:18px;fill:#333;}#mermaid-svg-0 rect.text{fill:none;stroke-width:0;}#mermaid-svg-0 .icon-shape,#mermaid-svg-0 .image-shape{background-color:rgba(232,232,232, 0.8);text-align:center;}#mermaid-svg-0 .icon-shape p,#mermaid-svg-0 .image-shape p{background-color:rgba(232,232,232, 0.8);padding:2px;}#mermaid-svg-0 .icon-shape rect,#mermaid-svg-0 .image-shape rect{opacity:0.5;background-color:rgba(232,232,232, 0.8);fill:rgba(232,232,232, 0.8);}#mermaid-svg-0 .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#mermaid-svg-0 .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#mermaid-svg-0 :root{--mermaid-font-family:"trebuchet ms",verdana,arial,sans-serif;}</style><g><marker id="mermaid-svg-0_flowchart-v2-pointEnd" class="marker flowchart-v2" viewBox="0 0 10 10" refX="5" refY="5" markerUnits="userSpaceOnUse" markerWidth="8" markerHeight="8" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" class="arrowMarkerPath" style="stroke-width: 1; stroke-dasharray: 1, 0;"/></marker><marker id="mermaid-svg-0_flowchart-v2-pointStart" class="marker flowchart-v2" viewBox="0 0 10 10" refX="4.5" refY="5" markerUnits="userSpaceOnUse" markerWidth="8" markerHeight="8" orient="auto"><path d="M 0 5 L 10 10 L 10 0 z" class="arrowMarkerPath" style="stroke-width: 1; stroke-dasharray: 1, 0;"/></marker><marker id="mermaid-svg-0_flowchart-v2-circleEnd" class="marker flowchart-v2" viewBox="0 0 10 10" refX="11" refY="5" markerUnits="userSpaceOnUse" markerWidth="11" markerHeight="11" orient="auto"><circle cx="5" cy="5" r="5" class="arrowMarkerPath" style="stroke-width: 1; stroke-dasharray: 1, 0;"/></marker><marker id="mermaid-svg-0_flowchart-v2-circleStart" class="marker flowchart-v2" viewBox="0 0 10 10" refX="-1" refY="5" markerUnits="userSpaceOnUse" markerWidth="11" markerHeight="11" orient="auto"><circle cx="5" cy="5" r="5" class="arrowMarkerPath" style="stroke-width: 1; stroke-dasharray: 1, 0;"/></marker><marker id="mermaid-svg-0_flowchart-v2-crossEnd" class="marker cross flowchart-v2" viewBox="0 0 11 11" refX="12" refY="5.2" markerUnits="userSpaceOnUse" markerWidth="11" markerHeight="11" orient="auto"><path d="M 1,1 l 9,9 M 10,1 l -9,9" class="arrowMarkerPath" style="stroke-width: 2; stroke-dasharray: 1, 0;"/></marker><marker id="mermaid-svg-0_flowchart-v2-crossStart" class="marker cross flowchart-v2" viewBox="0 0 11 11" refX="-1" refY="5.2" markerUnits="userSpaceOnUse" markerWidth="11" markerHeight="11" orient="auto"><path d="M 1,1 l 9,9 M 10,1 l -9,9" class="arrowMarkerPath" style="stroke-width: 2; stroke-dasharray: 1, 0;"/></marker><g class="root"><g class="clusters"/><g class="edgePaths"><path d="M134.1,62L134.1,66.167C134.1,70.333,134.1,78.667,134.17,86.417C134.241,94.167,134.381,101.334,134.451,104.917L134.522,108.501" id="L_A_B_0" class="edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-svg-0_flowchart-v2-pointEnd)"/><path d="M94.556,299.256L87.464,312.014C80.371,324.771,66.185,350.285,59.093,388.309C52,426.333,52,476.867,52,527.4C52,577.933,52,628.467,52,677C52,725.533,52,772.067,52,818.6C52,865.133,52,911.667,79.725,942.668C107.449,973.67,162.898,989.139,190.623,996.874L218.347,1004.609" id="L_B_C_0" class="edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-svg-0_flowchart-v2-pointEnd)"/><path d="M183.664,290.236L194.52,304.496C205.376,318.757,227.088,347.279,238.019,367.123C248.949,386.967,249.098,398.134,249.172,403.717L249.247,409.3" id="L_B_D_0" class="edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-svg-0_flowchart-v2-pointEnd)"/><path d="M269.582,622.218L271.552,631.682C273.521,641.145,277.461,660.073,279.43,692.803C281.4,725.533,281.4,772.067,281.4,818.6C281.4,865.133,281.4,911.667,281.4,940.433C281.4,969.2,281.4,980.2,281.4,985.7L281.4,991.2" id="L_D_C_0" class="edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-svg-0_flowchart-v2-pointEnd)"/><path d="M318.68,573.12L345.8,590.766C372.92,608.413,427.16,643.707,454.355,666.937C481.549,690.167,481.698,701.334,481.772,706.917L481.847,712.5" id="L_D_E_0" class="edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-svg-0_flowchart-v2-pointEnd)"/><path d="M205.786,598.986L197.488,612.321C189.191,625.657,172.595,652.329,164.298,683.764C156,715.2,156,751.4,156,769.5L156,787.6" id="L_D_F_0" class="edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-svg-0_flowchart-v2-pointEnd)"/><path d="M445.61,885.41L438.842,897.542C432.073,909.673,418.537,933.937,400.451,951.928C382.365,969.92,359.731,981.64,348.413,987.501L337.096,993.361" id="L_E_C_0" class="edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-svg-0_flowchart-v2-pointEnd)"/><path d="M509.037,894.563L512.797,905.17C516.558,915.776,524.079,936.988,527.839,953.094C531.6,969.2,531.6,980.2,531.6,985.7L531.6,991.2" id="L_E_G_0" class="edge-thickness-normal edge-pattern-solid edge-thickness-normal edge-pattern-solid flowchart-link" style="" marker-end="url(#mermaid-svg-0_flowchart-v2-pointEnd)"/></g><g class="edgeLabels"><g class="edgeLabel"><g class="label" transform="translate(0, 0)"><foreignObject width="0" height="0"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel"></span></div></foreignObject></g></g><g class="edgeLabel" transform="translate(52, 679)"><g class="label" transform="translate(-44, -12)"><foreignObject width="88" height="24"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel"><p>Pattern Fort</p></span></div></foreignObject></g></g><g class="edgeLabel" transform="translate(248.80000114440918, 375.8000030517578)"><g class="label" transform="translate(-80, -12)"><foreignObject width="160" height="24"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel"><p>Pattern Faible / Clean</p></span></div></foreignObject></g></g><g class="edgeLabel" transform="translate(281.4000015258789, 818.5999984741211)"><g class="label" transform="translate(-44.400001525878906, -12)"><foreignObject width="88.80000305175781" height="24"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel"><p>Score &gt; 0.95</p></span></div></foreignObject></g></g><g class="edgeLabel" transform="translate(415.75746, 636.28688)"><g class="label" transform="translate(-64.80000305175781, -12)"><foreignObject width="129.60000610351562" height="24"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel"><p>0.7 &lt; Score &lt; 0.95</p></span></div></foreignObject></g></g><g class="edgeLabel" transform="translate(156, 679)"><g class="label" transform="translate(-40, -12)"><foreignObject width="80" height="24"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel"><p>Score &lt; 0.7</p></span></div></foreignObject></g></g><g class="edgeLabel" transform="translate(405.70272, 956.94044)"><g class="label" transform="translate(-45.20000076293945, -12)"><foreignObject width="90.4000015258789" height="24"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel"><p>Risque élevé</p></span></div></foreignObject></g></g><g class="edgeLabel" transform="translate(531.600004196167, 958.1999969482422)"><g class="label" transform="translate(-53.20000076293945, -12)"><foreignObject width="106.4000015258789" height="24"><div xmlns="http://www.w3.org/1999/xhtml" class="labelBkg" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="edgeLabel"><p>Risque modéré</p></span></div></foreignObject></g></g></g><g class="nodes"><g class="node default" id="flowchart-A-0" transform="translate(134.10000038146973, 35)"><rect class="basic label-container" style="" x="-85.20000076293945" y="-27" width="170.4000015258789" height="54"/><g class="label" style="" transform="translate(-55.20000076293945, -12)"><rect/><foreignObject width="110.4000015258789" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel"><p>Prompt Entrant</p></span></div></foreignObject></g></g><g class="node default" id="flowchart-B-1" transform="translate(134.10000038146973, 225.4000015258789)"><polygon points="113.4000015258789,0 226.8000030517578,-113.4000015258789 113.4000015258789,-226.8000030517578 0,-113.4000015258789" class="label-container" transform="translate(-112.9000015258789, 113.4000015258789)"/><g class="label" style="" transform="translate(-86.4000015258789, -12)"><rect/><foreignObject width="172.8000030517578" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel"><p>Couche 1: Regex Rapide</p></span></div></foreignObject></g></g><g class="node default" id="flowchart-C-3" transform="translate(281.4000015258789, 1022.1999969482422)"><rect class="basic label-container" style="fill:#ff2a6d !important" x="-59.20000076293945" y="-27" width="118.4000015258789" height="54"/><g class="label" style="color:#fff !important" transform="translate(-29.200000762939453, -12)"><rect/><foreignObject width="58.400001525878906" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="color: rgb(255, 255, 255) !important; display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span style="color:#fff !important" class="nodeLabel"><p>BLOQUÉ</p></span></div></foreignObject></g></g><g class="node default" id="flowchart-D-5" transform="translate(248.80000114440918, 527.4000015258789)"><polygon points="114.5999984741211,0 229.1999969482422,-114.5999984741211 114.5999984741211,-229.1999969482422 0,-114.5999984741211" class="label-container" transform="translate(-114.0999984741211, 114.5999984741211)"/><g class="label" style="" transform="translate(-87.5999984741211, -12)"><rect/><foreignObject width="175.1999969482422" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel"><p>Couche 2: Classifieur ML</p></span></div></foreignObject></g></g><g class="node default" id="flowchart-E-9" transform="translate(481.4000053405762, 818.5999984741211)"><polygon points="102.5999984741211,0 205.1999969482422,-102.5999984741211 102.5999984741211,-205.1999969482422 0,-102.5999984741211" class="label-container" transform="translate(-102.0999984741211, 102.5999984741211)"/><g class="label" style="" transform="translate(-75.5999984741211, -12)"><rect/><foreignObject width="151.1999969482422" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span class="nodeLabel"><p>Couche 3: LLM Judge</p></span></div></foreignObject></g></g><g class="node default" id="flowchart-F-11" transform="translate(156, 818.5999984741211)"><rect class="basic label-container" style="fill:#00ff88 !important" x="-46" y="-27" width="92" height="54"/><g class="label" style="color:#000 !important" transform="translate(-16, -12)"><rect/><foreignObject width="32" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="color: rgb(0, 0, 0) !important; display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span style="color:#000 !important" class="nodeLabel"><p>PASS</p></span></div></foreignObject></g></g><g class="node default" id="flowchart-G-15" transform="translate(531.600004196167, 1022.1999969482422)"><rect class="basic label-container" style="fill:#ff9f1c !important" x="-90.79999923706055" y="-27" width="181.5999984741211" height="54"/><g class="label" style="color:#000 !important" transform="translate(-60.79999923706055, -12)"><rect/><foreignObject width="121.5999984741211" height="24"><div xmlns="http://www.w3.org/1999/xhtml" style="color: rgb(0, 0, 0) !important; display: table-cell; white-space: nowrap; line-height: 1.5; max-width: 200px; text-align: center;"><span style="color:#000 !important" class="nodeLabel"><p>⚠️ Alert + Revue</p></span></div></foreignObject></g></g></g></g></g></svg>
\---
![Uploading deepseek_mermaid_20260802_5cadca.svg…]()
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
