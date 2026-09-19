from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from logscope.config import load_settings
from logscope.engine import AnalysisEngine
from logscope.parsers import parse_path
from logscope.reporting import build_markdown_report, write_json_findings
from logscope.storage import EventStore

app = typer.Typer(
    help="LogScope: ingest, analyze, and report on structured security and service logs.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def ingest(
    path: Annotated[Path, typer.Argument(help="CSV, JSONL, or NDJSON file to ingest.")],
) -> None:
    """Parse and store normalized log events."""
    settings = load_settings()
    store = EventStore(settings.database_path)

    if not path.exists():
        raise typer.BadParameter(f"File does not exist: {path}")

    try:
        count = store.insert_events(parse_path(path))
    except ValueError as exc:
        console.print(f"[red]Ingestion failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]Ingested {count} events[/green] into {settings.database_path}")


@app.command()
def analyze() -> None:
    """Run built-in detection rules against all ingested events."""
    settings = load_settings()
    store = EventStore(settings.database_path)
    events = store.all_events()

    engine = AnalysisEngine(
        failure_threshold=settings.failure_threshold,
        window_minutes=settings.window_minutes,
    )
    findings = engine.analyze(events)
    store.replace_findings(findings)

    table = Table(title="LogScope Findings")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Title")
    table.add_column("Events", justify="right")
    table.add_column("Source")

    for finding in findings:
        table.add_row(
            finding.severity.value.upper(),
            finding.rule_id,
            finding.title,
            str(finding.event_count),
            finding.source_ip or "-",
        )

    console.print(table)
    console.print(f"[green]Stored {len(findings)} findings[/green]")


@app.command()
def summary() -> None:
    """Show event and finding counts from the local database."""
    settings = load_settings()
    stats = EventStore(settings.database_path).summary()

    table = Table(title="LogScope Summary")
    table.add_column("Metric")
    table.add_column("Count", justify="right")
    table.add_row("Events", str(stats["events"]))
    table.add_row("Findings", str(stats["findings"]))
    table.add_row("High severity", str(stats["high_severity_findings"]))
    console.print(table)


@app.command()
def report(
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Markdown report output path."),
    ] = Path("logscope-report.md"),
    json_output: Annotated[
        Path | None,
        typer.Option("--json-output", help="Optional JSON findings output."),
    ] = None,
) -> None:
    """Analyze current events and generate a Markdown report."""
    settings = load_settings()
    store = EventStore(settings.database_path)
    events = store.all_events()

    engine = AnalysisEngine(
        failure_threshold=settings.failure_threshold,
        window_minutes=settings.window_minutes,
    )
    findings = engine.analyze(events)
    store.replace_findings(findings)

    output.write_text(build_markdown_report(events, findings), encoding="utf-8")

    if json_output is not None:
        write_json_findings(json_output, findings)

    console.print(f"[green]Report written to {output}[/green]")


if __name__ == "__main__":
    app()
