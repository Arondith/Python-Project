from datetime import UTC, datetime, timedelta

from logscope.engine import AnalysisEngine
from logscope.models import EventType, LogEvent


def make_event(
    event_id: int,
    *,
    minute: int,
    event_type: EventType,
    source_ip: str,
    username: str | None = None,
    status_code: int | None = None,
    service: str | None = None,
) -> tuple[int, LogEvent]:
    metadata = {"service": service} if service else {}
    return (
        event_id,
        LogEvent(
            timestamp=datetime(2026, 9, 19, 8, 0, tzinfo=UTC)
            + timedelta(minutes=minute),
            event_type=event_type,
            source_ip=source_ip,
            username=username,
            message="test event",
            status_code=status_code,
            metadata=metadata,
        ),
    )


def test_engine_detects_authentication_patterns() -> None:
    events = [
        make_event(
            index,
            minute=index,
            event_type=EventType.LOGIN_FAILURE,
            source_ip="203.0.113.10",
            username=f"user-{index}",
        )
        for index in range(1, 6)
    ]

    findings = AnalysisEngine(failure_threshold=5, window_minutes=10).analyze(events)
    rule_ids = {finding.rule_id for finding in findings}

    assert "AUTH-001" in rule_ids
    assert "AUTH-002" in rule_ids


def test_engine_does_not_alert_below_threshold() -> None:
    events = [
        make_event(
            index,
            minute=index,
            event_type=EventType.LOGIN_FAILURE,
            source_ip="203.0.113.10",
            username=f"user-{index}",
        )
        for index in range(1, 4)
    ]

    findings = AnalysisEngine(failure_threshold=5, window_minutes=10).analyze(events)

    assert findings == []


def test_engine_detects_http_error_burst() -> None:
    events = [
        make_event(
            index,
            minute=index,
            event_type=EventType.HTTP_REQUEST,
            source_ip=f"198.51.100.{index}",
            status_code=503,
            service="orders-api",
        )
        for index in range(1, 6)
    ]

    findings = AnalysisEngine(failure_threshold=5, window_minutes=10).analyze(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HTTP-001"
    assert findings[0].event_count == 5
