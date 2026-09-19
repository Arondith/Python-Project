from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from datetime import timedelta

from logscope.models import EventType, Finding, LogEvent, Severity

StoredEvent = tuple[int, LogEvent]


def detect_repeated_login_failures(
    events: Iterable[StoredEvent],
    *,
    threshold: int,
    window_minutes: int,
) -> list[Finding]:
    grouped: dict[str, list[StoredEvent]] = defaultdict(list)

    for stored in events:
        _, event = stored
        if event.event_type == EventType.LOGIN_FAILURE and event.source_ip:
            grouped[event.source_ip].append(stored)

    findings: list[Finding] = []

    for source_ip, group in grouped.items():
        window = _densest_window(group, window_minutes)
        if len(window) < threshold:
            continue

        first = window[0][1]
        last = window[-1][1]
        findings.append(
            Finding(
                rule_id="AUTH-001",
                title="Repeated login failures",
                severity=Severity.HIGH,
                summary=(
                    f"{len(window)} login failures from {source_ip} "
                    f"within {window_minutes} minutes."
                ),
                source_ip=source_ip,
                first_seen=first.timestamp,
                last_seen=last.timestamp,
                event_count=len(window),
                evidence=[event_id for event_id, _ in window],
            )
        )

    return findings


def detect_password_spray(
    events: Iterable[StoredEvent],
    *,
    distinct_user_threshold: int,
    window_minutes: int,
) -> list[Finding]:
    grouped: dict[str, list[StoredEvent]] = defaultdict(list)

    for stored in events:
        _, event = stored
        if (
            event.event_type == EventType.LOGIN_FAILURE
            and event.source_ip
            and event.username
        ):
            grouped[event.source_ip].append(stored)

    findings: list[Finding] = []

    for source_ip, group in grouped.items():
        window = _best_window(
            group,
            window_minutes,
            score=lambda rows: len({event.username for _, event in rows if event.username}),
        )
        usernames = {event.username for _, event in window if event.username}

        if len(usernames) < distinct_user_threshold:
            continue

        first = window[0][1]
        last = window[-1][1]
        findings.append(
            Finding(
                rule_id="AUTH-002",
                title="Possible password spray",
                severity=Severity.HIGH,
                summary=(
                    f"Login failures targeted {len(usernames)} distinct users "
                    f"from {source_ip} within {window_minutes} minutes."
                ),
                source_ip=source_ip,
                first_seen=first.timestamp,
                last_seen=last.timestamp,
                event_count=len(window),
                evidence=[event_id for event_id, _ in window],
            )
        )

    return findings


def detect_server_error_burst(
    events: Iterable[StoredEvent],
    *,
    threshold: int,
    window_minutes: int,
) -> list[Finding]:
    candidates = [
        stored
        for stored in events
        if stored[1].event_type == EventType.HTTP_REQUEST
        and stored[1].status_code is not None
        and stored[1].status_code >= 500
    ]

    by_service: dict[str, list[StoredEvent]] = defaultdict(list)
    for stored in candidates:
        _, event = stored
        service = str(event.metadata.get("service") or "unknown-service")
        by_service[service].append(stored)

    findings: list[Finding] = []

    for service, group in by_service.items():
        window = _densest_window(group, window_minutes)
        if len(window) < threshold:
            continue

        first = window[0][1]
        last = window[-1][1]
        findings.append(
            Finding(
                rule_id="HTTP-001",
                title="Server error burst",
                severity=Severity.MEDIUM,
                summary=(
                    f"{len(window)} HTTP 5xx responses for {service} "
                    f"within {window_minutes} minutes."
                ),
                first_seen=first.timestamp,
                last_seen=last.timestamp,
                event_count=len(window),
                evidence=[event_id for event_id, _ in window],
            )
        )

    return findings


def _densest_window(events: list[StoredEvent], window_minutes: int) -> list[StoredEvent]:
    return _best_window(events, window_minutes, score=len)


def _best_window(
    events: list[StoredEvent],
    window_minutes: int,
    *,
    score: Callable[[list[StoredEvent]], int],
) -> list[StoredEvent]:
    ordered = sorted(events, key=lambda item: item[1].timestamp)
    best: list[StoredEvent] = []
    best_score = 0
    left = 0
    window = timedelta(minutes=window_minutes)

    for right, (_, event) in enumerate(ordered):
        while event.timestamp - ordered[left][1].timestamp > window:
            left += 1

        candidate = ordered[left : right + 1]
        candidate_score = score(candidate)

        if candidate_score > best_score or (
            candidate_score == best_score and len(candidate) > len(best)
        ):
            best = candidate
            best_score = candidate_score

    return best
