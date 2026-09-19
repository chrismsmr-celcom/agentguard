"""Alert rule storage for Cerbere / AgentGuard.

SQLite/PostgreSQL compatible persistence for the alert-rule API.
"""
from __future__ import annotations

import logging
import math
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .db import get_db, is_postgres, sql_placeholder

logger = logging.getLogger("agentguard.alerts")

VALID_METRICS = frozenset({
    "cost_usd",
    "input_tokens",
    "output_tokens",
    "latency_ms",
    "total_spans",
    "blocked_spans",
    "block_rate",
    "error_rate",
})

VALID_COMPARISONS = frozenset({"above", "below", "equal", "gte", "lte"})
MAX_LABEL_LENGTH = 200
MIN_THRESHOLD = -1e18
MAX_THRESHOLD = 1e18


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: Any) -> dict[str, Any]:
    if row is None:
        return {}
    if isinstance(row, dict):
        return dict(row)
    if hasattr(row, "keys"):
        try:
            return {key: row[key] for key in row.keys()}
        except Exception:
            pass
    columns = [
        "id", "org_id", "metric", "comparison", "threshold", "label",
        "active", "created_by", "created_at", "updated_at",
    ]
    return dict(zip(columns, row))


def _normalize_label(label: Any) -> Optional[str]:
    if label is None:
        return None
    value = str(label).strip()
    if not value:
        return None
    if len(value) > MAX_LABEL_LENGTH:
        raise ValueError(f"label must be at most {MAX_LABEL_LENGTH} characters")
    return value


def _normalize_metric(metric: Any) -> str:
    value = str(metric or "").strip()
    if value not in VALID_METRICS:
        raise ValueError(f"metric must be one of {sorted(VALID_METRICS)}")
    return value


def _normalize_comparison(comparison: Any) -> str:
    value = str(comparison or "above").strip().lower()
    if value not in VALID_COMPARISONS:
        raise ValueError(f"comparison must be one of {sorted(VALID_COMPARISONS)}")
    return value


def _normalize_threshold(threshold: Any) -> float:
    if isinstance(threshold, bool):
        raise ValueError("threshold must be a number")
    try:
        value = float(threshold)
    except (TypeError, ValueError):
        raise ValueError("threshold must be a number") from None
    if not math.isfinite(value):
        raise ValueError("threshold must be a finite number")
    if value < MIN_THRESHOLD or value > MAX_THRESHOLD:
        raise ValueError("threshold is outside the supported range")
    return value


def _ensure_schema() -> None:
    """Create the alert_rules table and indexes if they do not exist."""
    db = get_db()
    try:
        if is_postgres():
            db.execute("""
                CREATE TABLE IF NOT EXISTS alert_rules (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    comparison TEXT NOT NULL,
                    threshold DOUBLE PRECISION NOT NULL,
                    label TEXT,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            db.execute("""
                CREATE TABLE IF NOT EXISTS alert_rules (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    comparison TEXT NOT NULL,
                    threshold REAL NOT NULL,
                    label TEXT,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

        db.execute("CREATE INDEX IF NOT EXISTS idx_alert_rules_org ON alert_rules(org_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_alert_rules_org_active ON alert_rules(org_id, active)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_alert_rules_metric ON alert_rules(org_id, metric)")
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        raise
    finally:
        db.close()


def _serialize_rule(row: Any) -> dict[str, Any]:
    data = _row_to_dict(row)
    active = data.get("active")
    if isinstance(active, str):
        active = active.lower() in {"1", "true", "t", "yes"}
    else:
        active = bool(active)

    threshold = data.get("threshold")
    try:
        threshold = float(threshold)
        if threshold.is_integer():
            threshold = int(threshold)
    except (TypeError, ValueError):
        pass

    return {
        "id": data.get("id"),
        "org_id": data.get("org_id"),
        "metric": data.get("metric"),
        "comparison": data.get("comparison"),
        "threshold": threshold,
        "label": data.get("label"),
        "active": active,
        "created_by": data.get("created_by"),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
    }


def create_alert_rule(*, org_id: str, metric: str, comparison: str = "above",
                      threshold: Any = None, label: Optional[str] = None,
                      created_by: Optional[str] = None) -> dict[str, Any]:
    """Create one organization-scoped alert rule."""
    org_id = str(org_id or "").strip()
    if not org_id:
        raise ValueError("org_id is required")

    metric = _normalize_metric(metric)
    comparison = _normalize_comparison(comparison)
    threshold = _normalize_threshold(threshold)
    label = _normalize_label(label)
    created_by = str(created_by).strip() if created_by is not None else None
    created_by = created_by or None

    _ensure_schema()
    db = get_db()
    p = sql_placeholder()
    rule_id = f"alert_{uuid.uuid4().hex}"
    timestamp = _now_iso()

    try:
        db.execute(f"""
            INSERT INTO alert_rules
                (id, org_id, metric, comparison, threshold, label, active,
                 created_by, created_at, updated_at)
            VALUES ({p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p})
        """, (
            rule_id, org_id, metric, comparison, threshold, label,
            True if is_postgres() else 1, created_by, timestamp, timestamp,
        ))
        db.commit()
        cursor = db.execute(f"""
            SELECT id, org_id, metric, comparison, threshold, label, active,
                   created_by, created_at, updated_at
            FROM alert_rules
            WHERE id = {p} AND org_id = {p}
            LIMIT 1
        """, (rule_id, org_id))
        row = cursor.fetchone()
        if row is None:
            raise RuntimeError("Alert rule was created but could not be retrieved")
        return _serialize_rule(row)
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        raise
    finally:
        db.close()


def list_alert_rules(*, org_id: str, active_only: bool = False) -> list[dict[str, Any]]:
    """List alert rules for exactly one organization."""
    org_id = str(org_id or "").strip()
    if not org_id:
        raise ValueError("org_id is required")
    _ensure_schema()
    db = get_db()
    p = sql_placeholder()
    query = f"""
        SELECT id, org_id, metric, comparison, threshold, label, active,
               created_by, created_at, updated_at
        FROM alert_rules
        WHERE org_id = {p}
    """
    params: list[Any] = [org_id]
    if active_only:
        query += f" AND active = {sql_true_for_query()}"
    query += " ORDER BY created_at DESC"
    try:
        return [_serialize_rule(row) for row in db.execute(query, tuple(params)).fetchall()]
    finally:
        db.close()


def sql_true_for_query() -> str:
    """Return a DB-native true literal for the alert SQL layer."""
    return "TRUE" if is_postgres() else "1"


def get_alert_rule(alert_id: str, *, org_id: str) -> Optional[dict[str, Any]]:
    """Retrieve one rule, scoped to its organization."""
    alert_id = str(alert_id or "").strip()
    org_id = str(org_id or "").strip()
    if not alert_id:
        raise ValueError("alert_id is required")
    if not org_id:
        raise ValueError("org_id is required")
    _ensure_schema()
    db = get_db()
    p = sql_placeholder()
    try:
        row = db.execute(f"""
            SELECT id, org_id, metric, comparison, threshold, label, active,
                   created_by, created_at, updated_at
            FROM alert_rules
            WHERE id = {p} AND org_id = {p}
            LIMIT 1
        """, (alert_id, org_id)).fetchone()
        return _serialize_rule(row) if row is not None else None
    finally:
        db.close()


def delete_alert_rule(alert_id: str, *, org_id: str) -> bool:
    """Delete one rule only when both ID and organization match."""
    alert_id = str(alert_id or "").strip()
    org_id = str(org_id or "").strip()
    if not alert_id:
        raise ValueError("alert_id is required")
    if not org_id:
        raise ValueError("org_id is required")
    _ensure_schema()
    db = get_db()
    p = sql_placeholder()
    try:
        cursor = db.execute(
            f"DELETE FROM alert_rules WHERE id = {p} AND org_id = {p}",
            (alert_id, org_id),
        )
        deleted = getattr(cursor, "rowcount", 0) == 1
        db.commit()
        return deleted
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        raise
    finally:
        db.close()


def set_alert_rule_active(alert_id: str, *, org_id: str, active: bool) -> Optional[dict[str, Any]]:
    """Enable/disable a rule without deleting it."""
    alert_id = str(alert_id or "").strip()
    org_id = str(org_id or "").strip()
    if not alert_id:
        raise ValueError("alert_id is required")
    if not org_id:
        raise ValueError("org_id is required")
    _ensure_schema()
    db = get_db()
    p = sql_placeholder()
    try:
        cursor = db.execute(f"""
            UPDATE alert_rules
            SET active = {p}, updated_at = {p}
            WHERE id = {p} AND org_id = {p}
        """, (True if is_postgres() else (1 if active else 0), _now_iso(), alert_id, org_id))
        if getattr(cursor, "rowcount", 0) == 0:
            db.rollback()
            return None
        db.commit()
        row = db.execute(f"""
            SELECT id, org_id, metric, comparison, threshold, label, active,
                   created_by, created_at, updated_at
            FROM alert_rules
            WHERE id = {p} AND org_id = {p}
            LIMIT 1
        """, (alert_id, org_id)).fetchone()
        return _serialize_rule(row) if row is not None else None
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        raise
    finally:
        db.close()


def comparison_matches(value: Any, comparison: str, threshold: Any) -> bool:
    """Evaluate a rule against one metric value without side effects."""
    try:
        current = float(value)
        target = _normalize_threshold(threshold)
    except (TypeError, ValueError):
        return False
    operator = _normalize_comparison(comparison)
    if operator == "above":
        return current > target
    if operator == "below":
        return current < target
    if operator == "equal":
        return current == target
    if operator == "gte":
        return current >= target
    if operator == "lte":
        return current <= target
    return False


def evaluate_alert_rules(*, org_id: str, metrics: dict[str, Any]) -> list[dict[str, Any]]:
    """Return active rules triggered by the supplied metrics."""
    triggered = []
    for rule in list_alert_rules(org_id=org_id, active_only=True):
        metric = rule["metric"]
        if metric in metrics and comparison_matches(metrics[metric], rule["comparison"], rule["threshold"]):
            triggered.append({**rule, "current_value": metrics[metric], "triggered": True})
    return triggered


__all__ = [
    "VALID_METRICS",
    "VALID_COMPARISONS",
    "create_alert_rule",
    "list_alert_rules",
    "get_alert_rule",
    "delete_alert_rule",
    "set_alert_rule_active",
    "comparison_matches",
    "evaluate_alert_rules",
]
