from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from pydantic import BaseModel, Field, field_validator


class EventType(StrEnum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    HTTP_REQUEST = "http_request"
    PROCESS_EVENT = "process_event"
    GENERIC = "generic"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class LogEvent(BaseModel):
    timestamp: datetime
    event_type: EventType = EventType.GENERIC
    source_ip: str | None = None
    username: str | None = None
    message: str
    status_code: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None

        try:
            return str(IPv4Address(value))
        except ValueError:
            return str(IPv6Address(value))


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    summary: str
    source_ip: str | None = None
    username: str | None = None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    evidence: list[int] = Field(default_factory=list)
