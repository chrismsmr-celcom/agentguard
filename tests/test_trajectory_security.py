from trajectory import (
    TrajectoryAnalyzer,
    TrajectoryEvent,
)


def test_trajectory_detects_escalation():

    trajectory = TrajectoryAnalyzer(
        agent_id="agent-1",
        session_id="session-1",
    )

    trajectory.add(
        TrajectoryEvent(
            event_type="input",
            taint_level="UNTRUSTED",
        )
    )

    trajectory.add(
        TrajectoryEvent(
            event_type="database_read",
            taint_level="CONFIDENTIAL",
            risk_score=60,
        )
    )

    trajectory.add(
        TrajectoryEvent(
            event_type="tool_call",
            tool_name="send_email",
            taint_level="CONFIDENTIAL",
            external_side_effect=True,
            risk_score=70,
        )
    )

    analysis = trajectory.analyze()

    assert analysis[
        "trajectory_escalation"
    ] is True

    assert analysis[
        "trajectory_risk_score"
    ] >= 80

    assert analysis[
        "decision"
    ] == "block"


def test_trajectory_detects_privilege_escalation():

    trajectory = TrajectoryAnalyzer(
        agent_id="agent-1"
    )

    trajectory.add(
        TrajectoryEvent(
            event_type="input",
            taint_level="UNTRUSTED",
            risk_score=60,
        )
    )

    trajectory.add(
        TrajectoryEvent(
            event_type="tool_call",
            tool_name="admin_panel",
            risk_score=90,
            metadata={
                "tool_category": "admin"
            },
        )
    )

    analysis = trajectory.analyze()

    assert analysis[
        "privilege_escalation"
    ] is True


def test_safe_trajectory_is_allowed():

    trajectory = TrajectoryAnalyzer(
        agent_id="agent-1"
    )

    trajectory.add(
        TrajectoryEvent(
            event_type="tool_call",
            tool_name="search",
            taint_level="PUBLIC",
            risk_score=5,
        )
    )

    analysis = trajectory.analyze()

    assert analysis[
        "decision"
    ] == "allow"


def test_blocked_actions_are_counted():

    trajectory = TrajectoryAnalyzer()

    trajectory.add(
        TrajectoryEvent(
            event_type="tool_call",
            tool_name="shell",
            risk_score=100,
            decision="block",
            blocked=True,
        )
    )

    analysis = trajectory.analyze()

    assert analysis[
        "blocked_actions"
    ] == 1

    assert analysis[
        "risky_actions"
    ] == 1


def test_trajectory_memory_is_bounded():

    trajectory = TrajectoryAnalyzer(
        max_events=3
    )

    for i in range(10):

        trajectory.add(
            TrajectoryEvent(
                event_type="tool_call",
                tool_name=f"tool-{i}",
            )
        )

    assert trajectory.length == 3
    assert (
        trajectory.last_event.tool_name
        == "tool-9"
    )
