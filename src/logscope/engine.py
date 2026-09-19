from __future__ import annotations

from logscope.models import Finding
from logscope.rules import (
    StoredEvent,
    detect_password_spray,
    detect_repeated_login_failures,
    detect_server_error_burst,
)


class AnalysisEngine:
    def __init__(self, *, failure_threshold: int, window_minutes: int) -> None:
        self.failure_threshold = failure_threshold
        self.window_minutes = window_minutes

    def analyze(self, events: list[StoredEvent]) -> list[Finding]:
        findings = [
            *detect_repeated_login_failures(
                events,
                threshold=self.failure_threshold,
                window_minutes=self.window_minutes,
            ),
            *detect_password_spray(
                events,
                distinct_user_threshold=self.failure_threshold,
                window_minutes=self.window_minutes,
            ),
            *detect_server_error_burst(
                events,
                threshold=self.failure_threshold,
                window_minutes=self.window_minutes,
            ),
        ]

        severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        return sorted(
            findings,
            key=lambda finding: (
                severity_order[finding.severity.value],
                finding.first_seen,
                finding.rule_id,
            ),
        )
