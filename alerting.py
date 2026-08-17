"""
═══════════════════════════════════════════════════════════════════
 🚨 AgentGuard Alerting — notifications temps réel
═══════════════════════════════════════════════════════════════════
 Envoie une alerte quand AgentGuard BLOQUE une opération
 HIGH ou CRITICAL.

 Canaux (optionnels, cumulables) :
   • Slack webhook   → AGENTGUARD_ALERT_SLACK_WEBHOOK
   • Webhook générique (JSON POST : PagerDuty, n8n, Make, Discord relay…)
                      → AGENTGUARD_ALERT_WEBHOOK_URL
   • Email SMTP      → AGENTGUARD_ALERT_EMAIL_TO + config SMTP

 Anti-spam :
   • AGENTGUARD_ALERT_MIN_RISK  (défaut: high)
   • AGENTGUARD_ALERT_COOLDOWN  (défaut: 300s par type de check + org)

 Non-bloquant : envoi en thread daemon → ne ralentit jamais le collector.

 Test manuel :  python alerting.py --test
═══════════════════════════════════════════════════════════════════
"""
import os
import time
import threading
import logging
from datetime import datetime, timezone

import requests

logger = logging.getLogger("agentguard.alerting")

# ── CONFIG (variables d'environnement) ────────────────────────────
SLACK_WEBHOOK = os.environ.get("AGENTGUARD_ALERT_SLACK_WEBHOOK", "")
GENERIC_WEBHOOK = os.environ.get("AGENTGUARD_ALERT_WEBHOOK_URL", "")
EMAIL_TO = os.environ.get("AGENTGUARD_ALERT_EMAIL_TO", "")
SMTP_HOST = os.environ.get("AGENTGUARD_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("AGENTGUARD_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("AGENTGUARD_SMTP_USER", "")
SMTP_PASS = os.environ.get("AGENTGUARD_SMTP_PASS", "")
MIN_RISK = os.environ.get("AGENTGUARD_ALERT_MIN_RISK", "high")
COOLDOWN = int(os.environ.get("AGENTGUARD_ALERT_COOLDOWN", "300"))
PUBLIC_URL = os.environ.get("AGENTGUARD_PUBLIC_URL", "")

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
RISK_COLOR = {"high": "#f5b84b", "critical": "#e0525f"}

# ── Anti-spam (cooldown par check+org) ────────────────────────────
_lock = threading.Lock()
_last_sent = {}


def enabled():
    """True si au moins un canal est configuré."""
    return bool(SLACK_WEBHOOK or GENERIC_WEBHOOK or (EMAIL_TO and SMTP_HOST))


def _should_send(key):
    now = time.time()
    with _lock:
        if now - _last_sent.get(key, 0) < COOLDOWN:
            return False
        _last_sent[key] = now
        return True


def send_alert(event):
    """
    Point d'entrée appelé par le collector lors d'un blocage.
    Ne lève JAMAIS d'exception, ne bloque JAMAIS l'appelant.

    event = {check_name, risk_level, org_id, trace_id, model,
             reason, prompt}
    """
    try:
        if not enabled():
            return
        risk = event.get("risk_level", "high")
        if RISK_ORDER.get(risk, 0) < RISK_ORDER.get(MIN_RISK, 2):
            return
        key = f"{event.get('check_name', 'unknown')}|{event.get('org_id', 'default')}"
        if not _should_send(key):
            return
        threading.Thread(target=_dispatch, args=(event,), daemon=True).start()
    except Exception as exc:
        logger.warning("alerting.send_alert error: %s", exc)


def _dispatch(event):
    if SLACK_WEBHOOK:
        _send_slack(event)
    if GENERIC_WEBHOOK:
        _send_webhook(event)
    if EMAIL_TO and SMTP_HOST:
        _send_email(event)


def _human_text(event):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"🚨 [{str(event.get('risk_level', 'high')).upper()}] "
        f"{event.get('check_name', 'unknown')} — opération bloquée",
        f"🕐 {now}",
        f"🏢 org: {event.get('org_id', 'default')}",
        f"🤖 modèle: {event.get('model') or '—'}",
        f"🧬 trace: {event.get('trace_id', '—')}",
        f"📛 raison: {(event.get('reason') or '—')[:200]}",
        f"💬 prompt: {(event.get('prompt') or '—')[:200]}",
    ]
    if PUBLIC_URL:
        lines.append(f"🔗 dashboard: {PUBLIC_URL}/trace/{event.get('trace_id', '')}")
    return "\n".join(lines)


def _send_slack(event):
    try:
        risk = event.get("risk_level", "high")
        payload = {
            "username": "AgentGuard 🛡️",
            "attachments": [{
                "color": RISK_COLOR.get(risk, "#f5b84b"),
                "title": f"[{str(risk).upper()}] {event.get('check_name', 'unknown')} bloqué",
                "text": _human_text(event),
            }],
        }
        r = requests.post(SLACK_WEBHOOK, json=payload, timeout=10)
        if r.status_code != 200:
            logger.warning("slack alert failed: %s %s", r.status_code, r.text[:200])
    except Exception as exc:
        logger.warning("slack alert error: %s", exc)


def _send_webhook(event):
    """JSON standard → branche PagerDuty, n8n, Make, Zapier, ton propre backend…"""
    try:
        payload = {
            "source": "agentguard",
            "type": "security.block",
            "severity": event.get("risk_level", "high"),
            "check_name": event.get("check_name", "unknown"),
            "org_id": event.get("org_id", "default"),
            "trace_id": event.get("trace_id", ""),
            "model": event.get("model"),
            "reason": (event.get("reason") or "")[:500],
            "prompt": (event.get("prompt") or "")[:500],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        r = requests.post(GENERIC_WEBHOOK, json=payload, timeout=10)
        if r.status_code >= 400:
            logger.warning("webhook alert failed: %s", r.status_code)
    except Exception as exc:
        logger.warning("webhook alert error: %s", exc)


def _send_email(event):
    try:
        import smtplib
        from email.mime.text import MIMEText

        risk = event.get("risk_level", "high")
        msg = MIMEText(_human_text(event), "plain", "utf-8")
        msg["Subject"] = (f"🚨 [AgentGuard] {str(risk).upper()} — "
                          f"{event.get('check_name', 'unknown')} bloqué")
        msg["From"] = SMTP_USER or "agentguard@localhost"
        msg["To"] = EMAIL_TO

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            try:
                server.starttls()
                server.ehlo()
            except smtplib.SMTPNotSupportedError:
                pass
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
    except Exception as exc:
        logger.warning("email alert error: %s", exc)


# ── CLI de test ────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="AgentGuard alerting test")
    ap.add_argument("--test", action="store_true", help="envoie une alerte de test")
    args = ap.parse_args()

    if args.test:
        if not enabled():
            print("❌ Aucun canal configuré (SLACK_WEBHOOK / WEBHOOK_URL / EMAIL)")
            raise SystemExit(1)
        send_alert({
            "check_name": "prompt_injection",
            "risk_level": "critical",
            "org_id": "default",
            "trace_id": "test-trace-000",
            "model": "gpt-4o",
            "reason": "Alerte de test — l'alerting AgentGuard fonctionne ✅",
            "prompt": "Ignore all previous instructions…",
        })
        time.sleep(3)  # laisse le thread envoyer
        print("✅ Alerte de test envoyée — vérifie ton canal")
