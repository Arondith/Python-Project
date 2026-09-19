from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from logscope.models import Finding, LogEvent


def build_markdown_report(
    events: Iterable[tuple[int, LogEvent]],
    findings: Iterable[Finding],
) -> str:
    event_rows = list(events)
    finding_rows = list(findings)
    event_types = Counter(event.event_type.value for _, event in event_rows)
    severities = Counter(finding.severity.value for finding in finding_rows)

    lines = [
        "# LogScope Analysis Report",
        "",
        "## Summary",
        "",
        f"- Events analyzed: **{len(event_rows)}**",
        f"- Findings: **{len(finding_rows)}**",
        f"- High severity: **{severities.get('high', 0)}**",
        f"- Medium severity: **{severities.get('medium', 0)}**",
        "",
        "## Event distribution",
        "",
        "| Event type | Count |",
        "| --- | ---: |",
    ]

    for event_type, count in sorted(event_types.items()):
        lines.append(f"| {event_type} | {count} |")

    lines.extend(["", "## Findings", ""])

    if not finding_rows:
        lines.append("No detection rules produced findings.")
    else:
        for finding in finding_rows:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- Rule: `{finding.rule_id}`",
                    f"- Severity: **{finding.severity.value.upper()}**",
                    f"- First seen: {finding.first_seen.isoformat()}",
                    f"- Last seen: {finding.last_seen.isoformat()}",
                    f"- Events: {finding.event_count}",
                    f"- Source IP: {finding.source_ip or 'N/A'}",
                    f"- Username: {finding.username or 'N/A'}",
                    "",
                    finding.summary,
                    "",
                ]
            )

    return "\n".join(lines).rstrip() + "\n"


def write_json_findings(path: Path, findings: Iterable[Finding]) -> None:
    payload = [finding.model_dump(mode="json") for finding in findings]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
