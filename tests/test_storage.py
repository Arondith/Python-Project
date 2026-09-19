from datetime import UTC, datetime
from pathlib import Path

from logscope.models import EventType, Finding, LogEvent, Severity
from logscope.storage import EventStore


def test_store_persists_events_findings_and_summary(tmp_path: Path) -> None:
    database = tmp_path / "logscope.db"
    store = EventStore(str(database))

    event = LogEvent(
        timestamp=datetime(2026, 9, 19, 8, 0, tzinfo=UTC),
        event_type=EventType.LOGIN_FAILURE,
        source_ip="203.0.113.10",
        username="alex",
        message="Invalid password",
    )

    assert store.insert_events([event]) == 1

    stored = store.all_events()
    assert len(stored) == 1
    assert stored[0][1].username == "alex"

    finding = Finding(
        rule_id="AUTH-001",
        title="Repeated login failures",
        severity=Severity.HIGH,
        summary="Test finding",
        source_ip="203.0.113.10",
        first_seen=event.timestamp,
        last_seen=event.timestamp,
        event_count=1,
        evidence=[stored[0][0]],
    )

    assert store.replace_findings([finding]) == 1
    assert store.summary() == {
        "events": 1,
        "findings": 1,
        "high_severity_findings": 1,
    }


def test_empty_insert_is_noop(tmp_path: Path) -> None:
    store = EventStore(str(tmp_path / "logscope.db"))

    assert store.insert_events([]) == 0
