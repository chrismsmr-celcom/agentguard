# 🐕‍🦺 Cerbere — The Three-Headed Guardian of AI Agents

Runtime Security & Observability for AI Agents
> **No agent passes unseen.**

Cerbere is a runtime security control plane for autonomous AI agents. It intercepts every LLM call and tool invocation, applies multi-layered security policies, and blocks threats in real-time.

## 🏛️ The Three Heads

One SDK. One Collector. Three detection layers.

⸻

Why Cerbere -- AgentGuard?

AI agents can call LLMs, APIs, databases, browsers, email systems, code interpreters, and other tools.

Traditional application security does not fully understand these interactions.

AgentGuard provides a runtime security layer designed specifically for agentic workflows:

                 ┌──────────────────────┐
                 │      AI AGENT        │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │     AgentGuard SDK   │
                 │                      │
                 │  Policy Enforcement  │
                 │  Security Checks     │
                 │  Budget Controls     │
                 │  Tool Controls       │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │   3-Layer Detection  │
                 │                      │
                 │  1. Regex / Rules    │
                 │  2. ML Classifier    │
                 │  3. LLM Judge        │
                 └──────────┬───────────┘
                            │
                 ┌──────────┴───────────┐
                 ▼                      ▼
             🟢 ALLOW               🔴 BLOCK
                 │
                 ▼
          ┌─────────────────┐
          │    Collector    │
          │                 │
          │ Traces          │
          │ Metrics         │
          │ Security Events │
          │ Cost / Usage    │
          └────────┬────────┘
                   │
                   ▼
             📊 Dashboard

⸻

✨ Core Capabilities

🔍 AI Observability

* Real-time agent traces
* LLM calls and tool calls
* Latency monitoring
* Token / cost tracking
* Session information
* Security events
* Detection statistics

🛡️ Runtime Security

* Prompt injection detection
* PII detection and redaction
* Tool-use policy enforcement
* Tool allowlists
* Budget enforcement
* Suspicious behavior detection
* Runtime blocking
* Risk scoring

🧠 Multi-Layer Detection

Cerbere -- AgentGuard combines three detection mechanisms:

1. Rules / Regex — fast deterministic checks
2. ML Classifier — semantic threat detection
3. LLM Judge — analysis of ambiguous cases

This allows the system to use inexpensive deterministic checks first and reserve more expensive analysis for uncertain cases.

⸻

🛡️ Three-Layer Security Engine

flowchart TD
    A[Incoming Prompt / Tool Call] --> B{Layer 1<br/>Rules + Regex}
    B -->|Strong malicious pattern| X[BLOCK]
    B -->|Clean / uncertain| C{Layer 2<br/>ML Classifier}
    C -->|High risk| X
    C -->|Low risk| P[PASS]
    C -->|Ambiguous| D{Layer 3<br/>LLM Judge}
    D -->|High risk| X
    D -->|Moderate risk| R[ALERT / REVIEW]
    D -->|Low risk| P

Detection flow

Layer	Technology	Purpose
1	Rules / Regex	Fast deterministic detection
2	ML	Semantic classification
3	LLM Judge	Ambiguous or complex cases

The exact thresholds are configurable.

⸻

🚨 Threat Coverage

Threat	Rules	ML	LLM Judge	Possible Action
Prompt Injection	✅	✅	✅	Block
PII Leakage	✅	✅	✅	Redact / Block
Tool Misuse	✅	✅	✅	Block
Unauthorized Tools	✅	—	—	Block
Budget Overflow	✅	—	—	Block
Suspicious Input	✅	✅	✅	Alert
Ambiguous Behavior	—	⚠️	✅	Review

Cerbere -- AgentGuard is intended to provide defense in depth, not a guarantee that every attack will be detected.

⸻

🚀 Quick Start

Requirements

* Python 3.11+
* pip

1. Clone

git clone https://github.com/chrismsmr-celcom/agentguard.git
cd agentguard

2. Install

pip install -r requirements.txt

Optional ML dependencies:

pip install -r requirements-ml.txt

3. Start the Collector

python collector.py

The default collector runs on:

http://localhost:8080

4. Run the example agent

python example_agent.py

5. Check the API

curl http://localhost:8080/api/metrics

⸻

🐳 Docker

Docker Compose provides a convenient deployment environment.

cp env.example .env

Generate an API key:

python -c "import secrets; print('ag-' + secrets.token_urlsafe(32))"

Set the key in .env, then:

docker compose up -d

Services can include:

* AgentGuard Collector
* PostgreSQL
* Redis
* Gunicorn
* Health checks
* Persistent storage

⸻

🔌 SDK Integration

AgentGuard can wrap LLM and tool execution.

from agentguard_sdk import AgentGuard
guard = AgentGuard(
    collector_url="http://localhost:8080",
    api_key="ag-your-key",
    max_budget=10.0,
    block_on_high=True,
    use_ml=True,
    use_llm_judge=True,
)

Protect an LLM call

@guard.guard_llm_call
def call_openai(messages):
    return client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
    )

Protect a tool

@guard.guard_tool_call
def send_email(to, subject, body):
    return email_service.send(to, subject, body)

⸻

🔗 Integrations

Current examples include:

Integration	Support
LangChain	✅
CrewAI	✅
OpenAI	✅
DeepSeek	✅
Anthropic	✅

The SDK is designed to sit at the execution boundary rather than requiring changes to the underlying model.

⸻

🔧 Configuration

Example configuration:

# Authentication
AGENTGUARD_API_KEY=ag-your-key
# Database
AGENTGUARD_DB_TYPE=sqlite
# sqlite | postgres
DATABASE_URL=postgresql://user:pass@localhost:5432/agentguard
# ML
AGENTGUARD_USE_ML=true
AGENTGUARD_MODEL_PATH=./models/agentguard-injection-v1
AGENTGUARD_ML_THRESHOLD=0.80
# LLM Judge
AGENTGUARD_USE_LLM_JUDGE=true
DEEPSEEK_API_KEY=your-key
AGENTGUARD_JUDGE_MODEL=deepseek-chat
AGENTGUARD_BLOCK_ON_AMBIGUOUS=true
# Runtime
AGENTGUARD_RATE_LIMIT=300 per minute
AGENTGUARD_SPAN_RATE_LIMIT=150 per minute
AGENTGUARD_LOG_LEVEL=INFO

⸻

🧠 ML Detection

AgentGuard includes an optional ML detection pipeline.

Generate a dataset

python scripts/generate_dataset.py \
    --samples 50000 \
    --output dataset.csv

Train

python scripts/train_detector.py \
    --dataset dataset.csv \
    --output models/agentguard-injection-v1

Evaluate

python scripts/evaluate_detection.py \
    --model models/agentguard-injection-v1

Performance

The following are engineering targets, not guaranteed results:

Metric	Target
Recall	> 99%
Precision	> 98%
False Positive Rate	< 1%
Detection latency	< 50 ms

Actual performance must be established through reproducible benchmarks on an independent test set.

⸻

🎯 LLM Judge

The LLM Judge is designed for cases where deterministic rules and the ML classifier cannot confidently determine whether an interaction is malicious.

Example:

{
  "score": 88,
  "reason": "Potential attempt to bypass agent restrictions through contextual manipulation.",
  "is_attack": true
}

LLM Judge support is configurable and can be disabled when low latency or deterministic behavior is preferred.

⸻

📊 Observability Dashboard

AgentGuard includes a web dashboard for runtime monitoring.

Dashboard

http://localhost:8080/

Depending on the deployment configuration, the dashboard provides:

* Real-time traces
* Security alerts
* Risk distribution
* Activity metrics
* Cost monitoring
* Session information
* ML detection statistics
* LLM Judge statistics
* JSON log export

API endpoints

GET  /api/metrics
GET  /api/traces
GET  /api/detection/stats
GET  /api/llm/stats
GET  /trace/<trace-id>
POST /span

Authentication is required according to the configured security policy.

⸻

📁 Project Structure

agentguard/
│
├── agentguard_sdk.py
├── agentguard_ml.py
├── collector.py
├── example_agent.py
│
├── integrations/
│   ├── langchain_example.py
│   └── crewai_example.py
│
├── tests/
│   ├── test_security.py
│   └── test_detection.py
│
├── scripts/
│   ├── generate_dataset.py
│   ├── train_detector.py
│   └── evaluate_detection.py
│
├── requirements.txt
├── requirements-ml.txt
├── env.example
├── Dockerfile
├── docker-compose.yml
├── wsgi.py
├── LICENSE
└── README.md

⸻

🧪 Testing

Run the complete test suite:

pytest -q

Security-specific tests:

pytest tests/test_security.py -vv

Detection tests:

pytest tests/test_detection.py -vv

Security testing and independent evaluation are an ongoing part of the project.

⸻

🗺️ Roadmap

v4.x — Runtime Security Foundation

* Three-layer detection architecture
* Runtime telemetry
* Security events
* Dashboard
* PostgreSQL support
* Redis rate limiting
* Docker deployment
* ML detection pipeline
* LLM Judge integration

v5.x — Platform

* Multi-tenant architecture
* OpenTelemetry integration
* Alerting
* Slack / Email / PagerDuty integrations
* Dedicated CLI
* React dashboard
* Policy management
* Advanced RBAC

v6.x — AI Security Infrastructure

* High-performance collector
* Distributed detection
* Continuous model evaluation
* Automated threat intelligence
* Advanced agent behavior analysis
* Enterprise policy engine
* Security analytics

Roadmap items are subject to change.

⸻

🤝 Contributing

Contributions are welcome for permitted non-commercial development.

Typical workflow:

git clone <repository>
git checkout -b feature/my-feature

Make your changes, run the tests:

pytest -q

Then submit a Pull Request.

Before contributing, please read:

* LICENSE
* AUTHORS.md
* NOTICE.md
* CONTRIBUTING.md (if present)

⸻

📜 License

AgentGuard is source-available under a custom non-commercial license.

Commercial use is NOT permitted without written authorization.

This includes:

* Commercial SaaS
* Paid APIs
* Commercial software products
* Managed security services
* Commercial forks
* Selling modified versions
* Incorporating AgentGuard into a commercial product

Permitted non-commercial uses include:

* Personal use
* Education
* Academic research
* Security research
* Non-commercial experimentation
* Non-commercial contributions

Attribution to the original project and creator is required.

Copyright © 2026 Christopher Dikesa

See LICENSE for the complete terms.

⸻

🧾 Attribution

If you use or reference AgentGuard in research, documentation, presentations, or derivative non-commercial projects, please credit:

AgentGuard — created by Christopher Dikesa

Original project repository:

chrismsmr-celcom/agentguard

⸻

⚠️ Security Disclaimer

AgentGuard is a security layer designed to reduce risk in AI agent systems.

It does not guarantee complete protection against prompt injection, data leakage, tool abuse, model vulnerabilities, or other attacks.

Do not rely on AgentGuard as the sole security control for critical infrastructure.

If you discover a security vulnerability, please report it responsibly rather than publicly exposing exploitable details.

⸻

🙏 Acknowledgements

AgentGuard builds upon ideas, research, and tooling from the broader AI security ecosystem, including:

* OWASP LLM / GenAI security research
* Hugging Face
* DeepSeek
* Open-source Python ecosystem

⸻

<div align="center">

🛡️ AgentGuard

Observe. Detect. Enforce.

Runtime security infrastructure for agentic AI.

Copyright © 2026 Christopher Dikesa

</div>
