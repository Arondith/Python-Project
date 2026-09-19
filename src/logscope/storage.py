from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path

from logscope.models import Finding, LogEvent


class EventStore:
    def __init__(self, database_path: str) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    username TEXT,
                    message TEXT NOT NULL,
                    status_code INTEGER,
                    metadata_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_events_time
                    ON events(timestamp);

                CREATE INDEX IF NOT EXISTS idx_events_type_ip_time
                    ON events(event_type, source_ip, timestamp);

                CREATE INDEX IF NOT EXISTS idx_events_username_time
                    ON events(username, timestamp);

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    source_ip TEXT,
                    username TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    evidence_json TEXT NOT NULL
                );
                """
            )

    def insert_events(self, events: Iterable[LogEvent]) -> int:
        rows = [
            (
                event.timestamp.isoformat(),
                event.event_type.value,
                event.source_ip,
                event.username,
                event.message,
                event.status_code,
                json.dumps(event.metadata, sort_keys=True),
            )
            for event in events
        ]

        if not rows:
            return 0

        with self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO events (
                    timestamp,
                    event_type,
                    source_ip,
                    username,
                    message,
                    status_code,
                    metadata_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

        return len(rows)

    def all_events(self) -> list[tuple[int, LogEvent]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    id,
                    timestamp,
                    event_type,
                    source_ip,
                    username,
                    message,
                    status_code,
                    metadata_json
                FROM events
                ORDER BY timestamp, id
                """
            ).fetchall()

        return [
            (
                int(row["id"]),
                LogEvent.model_validate(
                    {
                        "timestamp": row["timestamp"],
                        "event_type": row["event_type"],
                        "source_ip": row["source_ip"],
                        "username": row["username"],
                        "message": row["message"],
                        "status_code": row["status_code"],
                        "metadata": json.loads(row["metadata_json"]),
                    }
                ),
            )
            for row in rows
        ]

    def replace_findings(self, findings: Iterable[Finding]) -> int:
        rows = [
            (
                finding.rule_id,
                finding.title,
                finding.severity.value,
                finding.summary,
                finding.source_ip,
                finding.username,
                finding.first_seen.isoformat(),
                finding.last_seen.isoformat(),
                finding.event_count,
                json.dumps(finding.evidence),
            )
            for finding in findings
        ]

        with self._connect() as connection:
            connection.execute("DELETE FROM findings")
            connection.executemany(
                """
                INSERT INTO findings (
                    rule_id,
                    title,
                    severity,
                    summary,
                    source_ip,
                    username,
                    first_seen,
                    last_seen,
                    event_count,
                    evidence_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

        return len(rows)

    def summary(self) -> dict[str, int]:
        with self._connect() as connection:
            event_count = int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            finding_count = int(connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
            high_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM findings WHERE severity = 'high'"
                ).fetchone()[0]
            )

        return {
            "events": event_count,
            "findings": finding_count,
            "high_severity_findings": high_count,
        }
