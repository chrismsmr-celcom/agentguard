"""
Secret detection patterns — extends PII redaction with secret detection.

Detects: JWT, AWS keys, GitHub PATs, Google API keys, private keys,
DB URLs, OAuth tokens, Stripe keys, Slack tokens, OpenAI/Anthropic keys.

Used by collector.db.redact_pii() to prevent secret leakage in:
- Database storage (spans table)
- Audit logs
- Error messages
- Alerting payloads
"""
import re
from typing import List, Tuple

# Pre-compiled patterns for secrets (high confidence, low false positives)
SECRET_PATTERNS: List[Tuple["re.Pattern", str]] = [
    # ── AWS ────────────────────────────────────────────────────
    # AWS Access Key ID (AKIA...)
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    # AWS Secret Access Key (typically 40 chars, base64-ish)
    # Use context to avoid false positives on random strings
    (re.compile(r"(?:aws_secret_access_key|secret_access_key|aws_secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", re.IGNORECASE), "[REDACTED_AWS_SECRET]"),
    
    # ── GitHub ─────────────────────────────────────────────────
    # GitHub PAT (classic)
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "[REDACTED_GITHUB_PAT]"),
    # GitHub PAT (fine-grained)
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}_[A-Za-z0-9]{59}\b"), "[REDACTED_GITHUB_PAT]"),
    # GitHub OAuth token
    (re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "[REDACTED_GITHUB_OAUTH]"),
    # GitHub user-to-server token
    (re.compile(r"\bghu_[A-Za-z0-9]{36}\b"), "[REDACTED_GITHUB_TOKEN]"),
    # GitHub server-to-server token
    (re.compile(r"\bghs_[A-Za-z0-9]{36}\b"), "[REDACTED_GITHUB_TOKEN]"),
    
    # ── Google ─────────────────────────────────────────────────
    # Google API key
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "[REDACTED_GOOGLE_KEY]"),
    # Google OAuth client secret
    (re.compile(r"(?:google_client_secret|gcp_secret)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{24,})['\"]?", re.IGNORECASE), "[REDACTED_GOOGLE_SECRET]"),
    
    # ── Slack ──────────────────────────────────────────────────
    # Slack tokens (bot, user, workspace, etc.)
    (re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}\b"), "[REDACTED_SLACK_TOKEN]"),
    # Slack webhook
    (re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+\b"), "[REDACTED_SLACK_WEBHOOK]"),
    
    # ── Stripe ─────────────────────────────────────────────────
    # Stripe secret key (live or test)
    (re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{24,}\b"), "[REDACTED_STRIPE_SECRET]"),
    # Stripe publishable key
    (re.compile(r"\bpk_(?:live|test)_[0-9A-Za-z]{24,}\b"), "[REDACTED_STRIPE_KEY]"),
    # Stripe webhook secret
    (re.compile(r"\bwhsec_[A-Za-z0-9]{32,}\b"), "[REDACTED_STRIPE_WEBHOOK]"),
    
    # ── JWT ────────────────────────────────────────────────────
    # JWT (header.payload.signature — 3 base64url segments separated by dots)
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,200}\.[A-Za-z0-9_-]{10,200}\.[A-Za-z0-9_-]{10,200}\b"), "[REDACTED_JWT]"),
    
    # ── Bearer tokens ──────────────────────────────────────────
    # Bearer token in Authorization header (long opaque strings)
    (re.compile(r"(?<=Bearer\s)[A-Za-z0-9._\-+/=]{32,}"), "[REDACTED_BEARER]"),
    
    # ── Private keys (PEM) ─────────────────────────────────────
    # RSA private key
    (re.compile(r"-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # Generic private key
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # EC private key
    (re.compile(r"-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    
    # ── Database URLs ──────────────────────────────────────────
    # PostgreSQL, MySQL, MongoDB, Redis connection strings
    (re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps)://[^\s'\"<>]+"), "[REDACTED_DB_URL]"),
    
    # ── OpenAI / Anthropic ─────────────────────────────────────
    # OpenAI API key
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b"), "[REDACTED_OPENAI_KEY]"),
    # Anthropic API key
    (re.compile(r"\bsk-ant-[A-Za-z0-9\-]{40,}\b"), "[REDACTED_ANTHROPIC_KEY]"),
    
    # ── Generic secrets (key=value patterns) ───────────────────
    # Common secret variable names with values
    (re.compile(
        r"\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
        r"secret[_-]?key|client[_-]?secret|private[_-]?key|"
        r"password|passwd|pwd|credentials?)\s*[=:]\s*['\"]?([A-Za-z0-9_\-+/=]{20,})['\"]?",
        re.IGNORECASE,
    ), "[REDACTED_GENERIC_SECRET]"),
]


def redact_secrets(text: str) -> str:
    """Redact secrets from a string.
    
    Args:
        text: Input string potentially containing secrets
    
    Returns:
        String with secrets replaced by [REDACTED_*] markers
    
    Example:
        >>> redact_secrets("My AWS key is AKIA1234567890ABCDEF")
        'My AWS key is [REDACTED_AWS_KEY]'
    """
    if not text or not isinstance(text, str):
        return text
    
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    
    return text
