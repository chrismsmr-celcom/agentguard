"""
Billing and subscription routes for AgentGuard.

Handles:
- Usage metrics and billing information
- Plan information and pricing
- Subscription management
- Invoice retrieval
"""

import os
import structlog
from flask import Blueprint, request, jsonify, g, render_template_string, current_app
from collector.auth import require_auth
from collector.db import get_db

logger = structlog.get_logger("agentguard.billing")
billing_bp = Blueprint("billing", __name__)


# ═══════════════════════════════════════════════════════════════
# BILLING PAGE TEMPLATE
# ═══════════════════════════════════════════════════════════════

BILLING_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Plans & Pricing — AgentGuard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-primary: #09090b;
            --bg-secondary: #18181b;
            --border-color: rgba(255, 255, 255, 0.08);
            --text-primary: #fafafa;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }
        .header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 1.5rem 0;
        }
        .header-content {
            max-width: 1000px;
            margin: 0 auto;
            padding: 0 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--accent-orange);
        }
        .container {
            max-width: 1000px;
            margin: 3rem auto;
            padding: 0 2rem;
        }
        h1 {
            font-size: 2rem;
            margin-bottom: 1rem;
        }
        .subtitle {
            color: var(--text-secondary);
            margin-bottom: 3rem;
            font-size: 1.1rem;
        }
        .plans-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }
        .plan-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 2rem;
            display: flex;
            flex-direction: column;
        }
        .plan-name {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        .plan-price {
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent-orange);
            margin-bottom: 1rem;
        }
        .plan-price-small {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        .plan-description {
            color: var(--text-secondary);
            margin-bottom: 1.5rem;
            flex-grow: 1;
        }
        .plan-features {
            list-style: none;
            margin-bottom: 1.5rem;
        }
        .plan-features li {
            padding: 0.5rem 0;
            color: var(--text-secondary);
        }
        .plan-features li:before {
            content: "✓ ";
            color: var(--accent-orange);
            font-weight: 600;
        }
        .plan-button {
            background: var(--accent-orange);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
            transition: opacity 0.2s;
        }
        .plan-button:hover {
            opacity: 0.9;
        }
        .plan-button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .back {
            display: inline-block;
            color: var(--text-secondary);
            text-decoration: none;
            margin-bottom: 1rem;
        }
        .back:hover {
            color: var(--text-primary);
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo">AgentGuard</div>
            <nav>
                <a href="/" style="color: var(--text-secondary); text-decoration: none;">Home</a>
            </nav>
        </div>
    </div>

    <div class="container">
        <a class="back" href="/dashboard">← Back to dashboard</a>
        
        <h1>Plans & Pricing</h1>
        <p class="subtitle">Choose the right plan for your AI agent monitoring needs.</p>
        
        <div class="plans-grid">
            <!-- Free Plan -->
            <div class="plan-card">
                <div class="plan-name">Free</div>
                <div class="plan-price">$0<span class="plan-price-small">/month</span></div>
                <p class="plan-description">Perfect for getting started with AgentGuard.</p>
                <ul class="plan-features">
                    <li>Up to 1 agent</li>
                    <li>Basic monitoring</li>
                    <li>Community support</li>
                    <li>7-day retention</li>
                </ul>
                <button class="plan-button" disabled>Current Plan</button>
            </div>

            <!-- Pro Plan -->
            <div class="plan-card">
                <div class="plan-name">Pro</div>
                <div class="plan-price">$99<span class="plan-price-small">/month</span></div>
                <p class="plan-description">For production AI agents with advanced monitoring.</p>
                <ul class="plan-features">
                    <li>Unlimited agents</li>
                    <li>Advanced security policies</li>
                    <li>Priority support</li>
                    <li>90-day retention</li>
                    <li>Custom rate limits</li>
                </ul>
                <button class="plan-button">Upgrade to Pro</button>
            </div>

            <!-- Enterprise Plan -->
            <div class="plan-card">
                <div class="plan-name">Enterprise</div>
                <div class="plan-price">Custom<span class="plan-price-small">Contact us</span></div>
                <p class="plan-description">For large-scale deployments with custom requirements.</p>
                <ul class="plan-features">
                    <li>Custom limits & features</li>
                    <li>Dedicated support</li>
                    <li>Long-term retention</li>
                    <li>SLA guarantee</li>
                    <li>On-premise option</li>
                </ul>
                <button class="plan-button">Contact Sales</button>
            </div>
        </div>

        <div style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 2rem; margin-top: 3rem;">
            <h2 style="margin-bottom: 1rem;">Usage & Billing</h2>
            <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                Billing information and usage metrics are coming soon. Automated payment processing is being finalized.
            </p>
            <p style="color: var(--text-muted); font-size: 0.9rem;">
                For now, pricing is based on your current plan. Contact us for custom arrangements.
            </p>
        </div>
    </div>
</body>
</html>
"""


# ═══════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════


@billing_bp.route("/billing")
def billing_page():
    """Display the billing and pricing page."""
    return render_template_string(BILLING_TEMPLATE)


@billing_bp.route("/api/billing/usage", methods=["GET"])
def get_usage():
    """
    Get current usage and billing metrics.
    
    Requires authentication. Multi-tenant: returns only org's data.
    """
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        db = get_db()
        
        # Multi-tenant isolation
        org_id = getattr(g, "org_id", None)
        if not org_id:
            return jsonify({"error": "No organization context"}), 400

        # Placeholder metrics - will be populated from actual usage data
        usage_metrics = {
            "org_id": org_id,
            "plan": "free",  # or "pro", "enterprise"
            "agents_count": 0,
            "spans_ingested": 0,
            "api_calls_this_month": 0,
            "storage_used_mb": 0,
            "reset_date": None,
        }

        return jsonify(usage_metrics), 200

    except Exception as e:
        logger.exception("billing_usage_error", error=str(e))
        return jsonify({"error": str(e)}), 500


@billing_bp.route("/api/billing/plan", methods=["GET"])
def get_plan():
    """
    Get the current plan for an organization.
    
    Requires authentication.
    """
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        org_id = getattr(g, "org_id", None)
        if not org_id:
            return jsonify({"error": "No organization context"}), 400

        # Placeholder plan info
        plan_info = {
            "org_id": org_id,
            "current_plan": "free",
            "agent_limit": 1,
            "retention_days": 7,
            "monthly_cost": 0,
            "features": [
                "Basic monitoring",
                "Community support",
            ],
            "upgrade_available": True,
        }

        return jsonify(plan_info), 200

    except Exception as e:
        logger.exception("billing_plan_error", error=str(e))
        return jsonify({"error": str(e)}), 500


@billing_bp.route("/api/billing/invoices", methods=["GET"])
def get_invoices():
    """
    Get invoices for the current organization.
    
    Requires authentication and billing permissions.
    """
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        org_id = getattr(g, "org_id", None)
        if not org_id:
            return jsonify({"error": "No organization context"}), 400

        # Placeholder: no invoices yet
        invoices = []

        return jsonify({
            "org_id": org_id,
            "invoices": invoices,
            "count": len(invoices),
        }), 200

    except Exception as e:
        logger.exception("billing_invoices_error", error=str(e))
        return jsonify({"error": str(e)}), 500


@billing_bp.route("/api/billing/upgrade", methods=["POST"])
def upgrade_plan():
    """
    Upgrade to a higher plan.
    
    Requires authentication and payment method on file.
    Automated payment processing coming soon.
    """
    if not require_auth():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        data = request.get_json() or {}
        target_plan = data.get("plan")
        
        if not target_plan:
            return jsonify({"error": "Missing 'plan' in request"}), 400

        if target_plan not in ["pro", "enterprise"]:
            return jsonify({"error": "Invalid plan"}), 400

        org_id = getattr(g, "org_id", None)
        if not org_id:
            return jsonify({"error": "No organization context"}), 400

        # Placeholder: payment processing not yet implemented
        logger.info(
            "billing_upgrade_requested",
            org_id=org_id,
            target_plan=target_plan,
            note="Automated payment processing being finalized",
        )

        return jsonify({
            "status": "pending",
            "message": "Upgrade request received. Automated payment processing is being finalized. Contact support for immediate upgrade.",
            "org_id": org_id,
            "requested_plan": target_plan,
        }), 202

    except Exception as e:
        logger.exception("billing_upgrade_error", error=str(e))
        return jsonify({"error": str(e)}), 500
