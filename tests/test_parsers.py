import json
from pathlib import Path

import pytest

from logscope.models import EventType
from logscope.parsers import parse_path


def test_parse_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        json.dumps(
            {
                "timestamp": "2026-09-19T08:00:00Z",
                "event_type": "login_success",
                "source_ip": "203.0.113.5",
                "username": "alex",
                "message": "Login successful",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = list(parse_path(path))

    assert len(events) == 1
    assert events[0].event_type == EventType.LOGIN_SUCCESS
    assert events[0].source_ip == "203.0.113.5"


def test_parse_csv(tmp_path: Path) -> None:
    path = tmp_path / "events.csv"
    path.write_text(
        "timestamp,event_type,source_ip,username,message,status_code,metadata\n"
        '2026-09-19T09:00:00Z,http_request,198.51.100.2,,Server error,503,"{""service"":""api""}"\n',
        encoding="utf-8",
    )

    events = list(parse_path(path))

    assert events[0].status_code == 503
    assert events[0].metadata["service"] == "api"


def test_parse_rejects_unsupported_format(tmp_path: Path) -> None:
    path = tmp_path / "events.txt"
    path.write_text("example", encoding="utf-8")

    with pytest.raises(ValueError, match="Supported input formats"):
        list(parse_path(path))


def test_parse_reports_invalid_json_line(tmp_path: Path) -> None:
    path = tmp_path / "broken.jsonl"
    path.write_text('{"broken":\n', encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid JSON on line 1"):
        list(parse_path(path))
