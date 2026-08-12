# Security Policy

## Reporting vulnerabilities

Do not open a public GitHub issue for an undisclosed vulnerability.

Report privately to the maintainer with:
- affected commit/version
- attack prerequisites
- reproduction steps or proof of concept
- impact
- redacted proof of concept

## Security requirements

- API credentials use `X-API-Key`; never put credentials in query parameters.
- Production deployments must use HTTPS.
- Prefer `AGENTGUARD_DETECTOR_FAILURE_MODE=fail_closed` for high-risk workloads.
- The LLM Judge is a detector, not an authorization authority.
- Tool execution must pass through an AgentGuard enforcement point before side effects.
- Never commit `AGENTGUARD_API_KEY`, `AGENTGUARD_ADMIN_SECRET`, `AGENTGUARD_FLASK_SECRET`, provider keys, or DB credentials.
