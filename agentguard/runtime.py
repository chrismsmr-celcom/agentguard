from typing import Optional, Dict, Any, List, Tuple
from .models import RuntimeRiskDecision, TrajectoryEvent, RiskLevel

class TrajectoryAnalyzer:
    _EXTERNAL_TOOLS = {"http_request", "fetch", "send_email", "webhook"}
    _IRREVERSIBLE_TOOLS = {"delete", "drop_database", "execute_command", "run_shell"}
    _PRIVILEGED_TOOLS = {"execute_command", "run_shell", "sudo", "admin_action"}

    def __init__(self, max_events: int = 100):
        self.max_events = max(10, int(max_events))
        self._events: Dict[str, List[TrajectoryEvent]] = {}

    def record(self, agent_id: str, event: TrajectoryEvent) -> None:
        events = self._events.setdefault(agent_id, [])
        events.append(event)
        if len(events) > self.max_events:
            del events[:-self.max_events]

    def events(self, agent_id: str) -> List[TrajectoryEvent]:
        return list(self._events.get(agent_id, []))

    def analyze(self, agent_id: str, tool_name: str, params: Optional[Dict[str, Any]] = None, taint_level: Optional[str] = None) -> Tuple[float, List[str], Dict[str, Any]]:
        score, reasons = 0.0, []
        external = tool_name in self._EXTERNAL_TOOLS
        irreversible = tool_name in self._IRREVERSIBLE_TOOLS
        privileged = tool_name in self._PRIVILEGED_TOOLS

        if taint_level in {"MALICIOUS", "SECRET"} and (external or privileged):
            score += 70
            reasons.append("sensitive taint reaches high-impact sink")
        if irreversible: score += 25; reasons.append("irreversible side effect")
        if privileged: score += 25; reasons.append("privileged tool")
        
        return min(100.0, score), reasons, {"external": external, "irreversible": irreversible, "privileged": privileged}

class RuntimeRiskEngine:
    def __init__(self, fail_closed: bool = True, approval_threshold: float = 55.0):
        self.fail_closed = bool(fail_closed)
        self.approval_threshold = max(0.0, min(100.0, float(approval_threshold)))

    def evaluate(self, tool_name: str, params: Optional[Dict[str, Any]], trajectory_score: float = 0.0, trajectory_reasons: Optional[List[str]] = None, trajectory_metadata: Optional[Dict[str, Any]] = None, taint_level: Optional[str] = None, local_check: Optional[Any] = None) -> RuntimeRiskDecision:
        score = float(trajectory_score)
        reasons = list(trajectory_reasons or [])
        metadata = dict(trajectory_metadata or {})
        
        if local_check is not None and not local_check.passed:
            score = max(score, 70.0)
            reasons.append(f"local policy: {local_check.details}")

        taint = str(taint_level or "").upper()
        if taint == "MALICIOUS" or (taint == "SECRET" and metadata.get("external")):
            return RuntimeRiskDecision("DENY", 100.0, RiskLevel.CRITICAL, reasons + ["hard rule violation"], metadata)

        if score >= 85:
            return RuntimeRiskDecision("DENY", score, RiskLevel.CRITICAL, reasons or ["critical runtime risk"], metadata)
        if score >= self.approval_threshold and (metadata.get("irreversible") or metadata.get("privileged")):
            return RuntimeRiskDecision("REQUIRE_APPROVAL", score, RiskLevel.HIGH, reasons or ["requires approval"], metadata)
        if score >= 65:
            return RuntimeRiskDecision("DENY", score, RiskLevel.HIGH, reasons or ["high runtime risk"], metadata)

        return RuntimeRiskDecision("ALLOW", score, RiskLevel.LOW, reasons, metadata)
