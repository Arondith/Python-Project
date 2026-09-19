from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from logscope.config import load_settings
from logscope.models import EventType, Finding, LogEvent, Severity
from logscope.reporting import build_markdown_report, write_json_findings


def test_naive_timestamp_is_normalized_to_utc() -> None:
    event = LogEvent(
        timestamp=datetime(2026, 9, 19, 8, 0),
        event_type=EventType.GENERIC,
        message="test",
    )

    assert event.timestamp.tzinfo == UTC


def test_invalid_ip_is_rejected() -> None:
    with pytest.raises(ValidationError):
        LogEvent(
            timestamp=datetime.now(UTC),
            source_ip="not-an-ip",
            message="test",
        )


def test_load_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOGSCOPE_DB", "/tmp/test.db")
    monkeypatch.setenv("LOGSCOPE_FAILURE_THRESHOLD", "7")
    monkeypatch.setenv("LOGSCOPE_WINDOW_MINUTES", "12")

    settings = load_settings()

    assert settings.database_path == "/tmp/test.db"
    assert settings.failure_threshold == 7
    assert settings.window_minutes == 12


def test_invalid_settings_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOGSCOPE_FAILURE_THRESHOLD", "1")

    with pytest.raises(ValueError, match="at least 2"):
        load_settings()


def test_markdown_and_json_reporting(tmp_path: Path) -> None:
    timestamp = datetime(2026, 9, 19, 8, 0, tzinfo=UTC)
    event = LogEvent(
        timestamp=timestamp,
        event_type=EventType.LOGIN_FAILURE,
        source_ip="203.0.113.10",
        message="Invalid password",
    )
    finding = Finding(
        rule_id="AUTH-001",
        title="Repeated login failures",
        severity=Severity.HIGH,
        summary="Five failures detected.",
        source_ip="203.0.113.10",
        first_seen=timestamp,
        last_seen=timestamp,
        event_count=5,
        evidence=[1, 2, 3, 4, 5],
    )

    report = build_markdown_report([(1, event)], [finding])

    assert "# LogScope Analysis Report" in report
    assert "AUTH-001" in report

    path = tmp_path / "findings.json"
    write_json_findings(path, [finding])

    assert '"rule_id": "AUTH-001"' in path.read_text(encoding="utf-8")
