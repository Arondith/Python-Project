from pathlib import Path

from typer.testing import CliRunner

from logscope.cli import app

runner = CliRunner()


def test_cli_end_to_end(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    database = tmp_path / "logscope.db"
    report = tmp_path / "report.md"
    sample = Path("examples/sample-events.jsonl")

    monkeypatch.setenv("LOGSCOPE_DB", str(database))

    ingest_result = runner.invoke(app, ["ingest", str(sample)])
    assert ingest_result.exit_code == 0
    assert "Ingested 11 events" in ingest_result.stdout

    analyze_result = runner.invoke(app, ["analyze"])
    assert analyze_result.exit_code == 0
    assert "AUTH-001" in analyze_result.stdout
    assert "AUTH-002" in analyze_result.stdout
    assert "HTTP-001" in analyze_result.stdout

    report_result = runner.invoke(app, ["report", "--output", str(report)])
    assert report_result.exit_code == 0
    assert report.exists()
    assert "LogScope Analysis Report" in report.read_text(encoding="utf-8")
