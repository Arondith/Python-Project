from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from logscope.models import LogEvent


def parse_jsonl(path: Path) -> Iterator[LogEvent]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc.msg}") from exc

            yield LogEvent.model_validate(payload)


def parse_csv_file(path: Path) -> Iterator[LogEvent]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)

        for row_number, row in enumerate(reader, start=2):
            try:
                payload = _csv_row_to_payload(row)
                yield LogEvent.model_validate(payload)
            except Exception as exc:
                raise ValueError(f"Invalid CSV record on row {row_number}: {exc}") from exc


def parse_path(path: Path) -> Iterable[LogEvent]:
    suffix = path.suffix.lower()

    if suffix in {".jsonl", ".ndjson"}:
        return parse_jsonl(path)

    if suffix == ".csv":
        return parse_csv_file(path)

    raise ValueError("Supported input formats are .jsonl, .ndjson, and .csv")


def _csv_row_to_payload(row: dict[str, str | None]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "timestamp": row.get("timestamp"),
        "event_type": row.get("event_type") or "generic",
        "source_ip": row.get("source_ip") or None,
        "username": row.get("username") or None,
        "message": row.get("message") or "",
        "status_code": _optional_int(row.get("status_code")),
    }

    metadata = row.get("metadata")
    if metadata:
        payload["metadata"] = json.loads(metadata)

    return payload


def _optional_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    return int(value)
