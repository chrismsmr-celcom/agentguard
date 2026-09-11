
"""
Approval lifecycle storage for Cerbere / AgentGuard.

HITL flow:

    ToolGuard
        |
        v
    REQUIRE_APPROVAL
        |
        v
    create_approval()
        |
        v
    PENDING
        |
        +----> APPROVED
        |
        +----> REJECTED
        |
        +----> EXPIRED

This module only manages the approval lifecycle.
It does NOT execute tools.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .db import get_db, is_postgres, sql_placeholder


APPROVAL_TTL_SECONDS = int(
    os.getenv("AGENTGUARD_APPROVAL_TTL_SECONDS", "600")
)

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
EXPIRED = "expired"

VALID_STATUSES = {
    PENDING,
    APPROVED,
    REJECTED,
    EXPIRED,
}


def _now() -> datetime:
    """Return current UTC time."""
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    """Serialize datetime as ISO-8601."""
    return dt.astimezone(timezone.utc).isoformat()


def _parse_datetime(value: Any) -> Optional[datetime]:
    """Parse stored datetime safely."""
    if value is None:
        return None

    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value)

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def _serialize_arguments(arguments: Any) -> str:
    """Serialize tool arguments for durable storage."""
    try:
        return json.dumps(
            arguments if arguments is not None else {},
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
    except Exception:
        return json.dumps({"_serialization_error": True})


def _deserialize_arguments(value: Any) -> Any:
    """Deserialize stored tool arguments."""
    if value is None:
        return {}

    if isinstance(value, (dict, list)):
        return value

    try:
        return json.loads(str(value))
    except Exception:
        return {"_raw": str(value)}


def _row_to_dict(row: Any) -> dict[str, Any]:
    """Convert SQLite/Postgres row into a normal dictionary."""
    if row is None:
        return {}

    if hasattr(row, "keys"):
        data = {key: row[key] for key in row.keys()}
    else:
        # PostgreSQL fallback if cursor returns tuples.
        columns = [
            "approval_id",
            "org_id",
            "tenant_id",
            "agent_id",
            "session_id",
            "trace_id",
            "span_id",
            "tool_name",
            "arguments",
            "risk_score",
            "reason",
            "policy_name",
            "status",
            "requested_at",
            "expires_at",
            "decided_at",
            "decided_by",
            "decision_reason",
        ]

        data = dict(zip(columns, row))

    data["arguments"] = _deserialize_arguments(data.get("arguments"))

    return data


def ensure_approval_schema() -> None:
    """
    Create the approval table if it does not exist.

    Safe to call during application startup or before the first approval.
    """

    db = get_db()

    if is_postgres():
        query = """
        CREATE TABLE IF NOT EXISTS approval_requests (
            approval_id TEXT PRIMARY KEY,
            org_id TEXT,
            tenant_id TEXT,
            agent_id TEXT,
            session_id TEXT,
            trace_id TEXT,
            span_id TEXT,
            tool_name TEXT NOT NULL,
            arguments TEXT NOT NULL,
            risk_score REAL,
            reason TEXT,
            policy_name TEXT,
            status TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            decided_at TEXT,
            decided_by TEXT,
            decision_reason TEXT
        )
        """
    else:
        query = """
        CREATE TABLE IF NOT EXISTS approval_requests (
            approval_id TEXT PRIMARY KEY,
            org_id TEXT,
            tenant_id TEXT,
            agent_id TEXT,
            session_id TEXT,
            trace_id TEXT,
            span_id TEXT,
            tool_name TEXT NOT NULL,
            arguments TEXT NOT NULL,
            risk_score REAL,
            reason TEXT,
            policy_name TEXT,
            status TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            decided_at TEXT,
            decided_by TEXT,
            decision_reason TEXT
        )
        """

    db.execute(query)
    db.commit()


def create_approval(
    *,
    tool_name: str,
    arguments: Any,
    org_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    session_id: Optional[str] = None,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    risk_score: Optional[float] = None,
    reason: Optional[str] = None,
    policy_name: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
) -> dict[str, Any]:
    """
    Create a new pending approval request.

    Returns the complete approval object.
    """

    ensure_approval_schema()

    now = _now()

    ttl = (
        APPROVAL_TTL_SECONDS
        if ttl_seconds is None
        else max(1, int(ttl_seconds))
    )

    expires_at = now + timedelta(seconds=ttl)

    approval_id = f"apr_{secrets.token_urlsafe(18)}"

    db = get_db()

    query = """
        INSERT INTO approval_requests (
            approval_id,
            org_id,
            tenant_id,
            agent_id,
            session_id,
            trace_id,
            span_id,
            tool_name,
            arguments,
            risk_score,
            reason,
            policy_name,
            status,
            requested_at,
            expires_at,
            decided_at,
            decided_by,
            decision_reason
        )
        VALUES (
            {p},{p},{p},{p},{p},{p},{p},{p},
            {p},{p},{p},{p},{p},{p},{p},{p},{p},{p}
        )
    """.format(p=sql_placeholder())

    params = (
        approval_id,
        org_id,
        tenant_id,
        agent_id,
        session_id,
        trace_id,
        span_id,
        tool_name,
        _serialize_arguments(arguments),
        risk_score,
        reason,
        policy_name,
        PENDING,
        _iso(now),
        _iso(expires_at),
        None,
        None,
        None,
    )

    db.execute(query, params)
    db.commit()

    return get_approval(approval_id)  # type: ignore[return-value]


def _expire_if_needed(approval: dict[str, Any]) -> dict[str, Any]:
    """
    Automatically transition an expired pending approval to EXPIRED.
    """

    if approval.get("status") != PENDING:
        return approval

    expires_at = _parse_datetime(approval.get("expires_at"))

    if expires_at is None:
        return approval

    if _now() < expires_at:
        return approval

    db = get_db()

    placeholder = sql_placeholder()

    query = f"""
        UPDATE approval_requests
        SET
            status = {placeholder},
            decided_at = {placeholder},
            decision_reason = {placeholder}
        WHERE approval_id = {placeholder}
          AND status = {placeholder}
    """

    now = _iso(_now())

    db.execute(
        query,
        (
            EXPIRED,
            now,
            "Approval request expired",
            approval["approval_id"],
            PENDING,
        ),
    )

    db.commit()

    return get_approval(approval["approval_id"]) or approval


def get_approval(
    approval_id: str,
    *,
    org_id: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """
    Retrieve one approval request.

    If org_id is supplied, the request must belong to that organization.
    """

    ensure_approval_schema()

    db = get_db()

    placeholder = sql_placeholder()

    if org_id is None:
        query = f"""
            SELECT *
            FROM approval_requests
            WHERE approval_id = {placeholder}
            LIMIT 1
        """

        cursor = db.execute(query, (approval_id,))
    else:
        query = f"""
            SELECT *
            FROM approval_requests
            WHERE approval_id = {placeholder}
              AND org_id = {placeholder}
            LIMIT 1
        """

        cursor = db.execute(query, (approval_id, org_id))

    row = cursor.fetchone()

    if row is None:
        return None

    approval = _row_to_dict(row)

    return _expire_if_needed(approval)


def list_approvals(
    *,
    org_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """
    List approval requests.

    Expired pending requests are automatically transitioned to EXPIRED.
    """

    ensure_approval_schema()

    limit = max(1, min(int(limit), 200))

    db = get_db()

    placeholder = sql_placeholder()

    conditions: list[str] = []
    params: list[Any] = []

    if org_id is not None:
        conditions.append(f"org_id = {placeholder}")
        params.append(org_id)

    if status is not None:
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid approval status: {status}")

        conditions.append(f"status = {placeholder}")
        params.append(status)

    where_clause = ""

    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    # LIMIT cannot safely use the same placeholder strategy across
    # all supported database drivers, so it is validated as an integer
    # and interpolated directly.
    query = f"""
        SELECT *
        FROM approval_requests
        {where_clause}
        ORDER BY requested_at DESC
        LIMIT {limit}
    """

    cursor = db.execute(query, tuple(params))

    approvals = [
        _expire_if_needed(_row_to_dict(row))
        for row in cursor.fetchall()
    ]

    # If the requested status is pending, expiration may have changed
    # some results. Re-filter after lifecycle processing.
    if status is not None:
        approvals = [
            approval
            for approval in approvals
            if approval.get("status") == status
        ]

    return approvals


def decide_approval(
    approval_id: str,
    *,
    decision: str,
    decided_by: Optional[str] = None,
    decision_reason: Optional[str] = None,
    org_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Approve or reject a pending approval request.

    This operation is concurrency-safe:
    only one caller can transition PENDING -> APPROVED/REJECTED.
    """

    ensure_approval_schema()

    normalized = str(decision).strip().lower()

    if normalized not in {APPROVED, REJECTED}:
        raise ValueError(
            "decision must be 'approved' or 'rejected'"
        )

    approval = get_approval(
        approval_id,
        org_id=org_id,
    )

    if approval is None:
        raise KeyError(f"Approval not found: {approval_id}")

    if approval["status"] == EXPIRED:
        raise ValueError("Approval request has expired")

    if approval["status"] != PENDING:
        raise ValueError(
            f"Approval request is already {approval['status']}"
        )

    expires_at = _parse_datetime(approval.get("expires_at"))

    if expires_at is not None and _now() >= expires_at:
        _expire_if_needed(approval)
        raise ValueError("Approval request has expired")

    db = get_db()

    placeholder = sql_placeholder()

    now = _iso(_now())

    # Important:
    # The WHERE status = pending clause makes the transition atomic.
    # Two simultaneous approvers cannot both successfully decide it.
    query = f"""
        UPDATE approval_requests
        SET
            status = {placeholder},
            decided_at = {placeholder},
            decided_by = {placeholder},
            decision_reason = {placeholder}
        WHERE approval_id = {placeholder}
          AND status = {placeholder}
    """

    params = (
        normalized,
        now,
        decided_by,
        decision_reason,
        approval_id,
        PENDING,
    )

    if org_id is not None:
        query += f"""
          AND org_id = {placeholder}
        """
        params = params + (org_id,)

    cursor = db.execute(query, params)
    db.commit()

    if getattr(cursor, "rowcount", 1) == 0:
        current = get_approval(
            approval_id,
            org_id=org_id,
        )

        if current is None:
            raise KeyError(f"Approval not found: {approval_id}")

        if current["status"] == EXPIRED:
            raise ValueError("Approval request has expired")

        raise ValueError(
            f"Approval request is already {current['status']}"
        )

    result = get_approval(
        approval_id,
        org_id=org_id,
    )

    if result is None:
        raise RuntimeError(
            "Approval was updated but could not be retrieved"
        )

    return result


def approve_approval(
    approval_id: str,
    *,
    decided_by: Optional[str] = None,
    decision_reason: Optional[str] = None,
    org_id: Optional[str] = None,
) -> dict[str, Any]:
    """Convenience wrapper for approving an approval request."""

    return decide_approval(
        approval_id,
        decision=APPROVED,
        decided_by=decided_by,
        decision_reason=decision_reason,
        org_id=org_id,
    )


def reject_approval(
    approval_id: str,
    *,
    decided_by: Optional[str] = None,
    decision_reason: Optional[str] = None,
    org_id: Optional[str] = None,
) -> dict[str, Any]:
    """Convenience wrapper for rejecting an approval request."""

    return decide_approval(
        approval_id,
        decision=REJECTED,
        decided_by=decided_by,
        decision_reason=decision_reason,
        org_id=org_id,
    )
