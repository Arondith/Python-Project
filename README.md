# LogScope

**LogScope** is a typed Python log-analysis and incident-triage toolkit for ingesting structured logs, detecting suspicious patterns, storing results, and generating reports.

It is designed as a Python portfolio project that demonstrates software engineering beyond basic scripting.

## What it demonstrates

- Python 3.12+
- installable Python package structure
- strict type hints
- Pydantic runtime validation
- CSV / JSONL / NDJSON parsing
- SQLite persistence
- database indexes
- defensive security analytics
- sliding-window event analysis
- command-line application development
- Rich terminal output
- Typer
- Markdown and JSON reporting
- pytest
- branch coverage
- Ruff
- mypy
- Docker
- GitHub Actions CI

## Detection rules

LogScope currently detects:

| Rule | Detection | Severity |
| --- | --- | --- |
| `AUTH-001` | Repeated login failures from one source | High |
| `AUTH-002` | Possible password spray across multiple usernames | High |
| `HTTP-001` | Burst of HTTP 5xx responses for a service | Medium |

The project is defensive: it analyzes supplied event data and surfaces patterns for review.

## Project structure

```text
src/logscope/
  cli.py
  config.py
  engine.py
  models.py
  parsers.py
  reporting.py
  rules.py
  storage.py

tests/
  test_cli.py
  test_models_config_reporting.py
  test_parsers.py
  test_rules.py
  test_storage.py

examples/
  sample-events.jsonl

docs/
  ARCHITECTURE.md
```

## Install

Clone the repository and install it in editable mode:

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

macOS/Linux:

```bash
source .venv/bin/activate
pip install -e ".[dev]"
```

## Try the sample data

### 1. Ingest

```bash
logscope ingest examples/sample-events.jsonl
```

### 2. Analyze

```bash
logscope analyze
```

The sample data produces authentication findings and an HTTP server-error finding.

### 3. View summary

```bash
logscope summary
```

### 4. Generate a report

```bash
logscope report --output logscope-report.md --json-output findings.json
```

## Supported event format

Example JSONL event:

```json
{
  "timestamp": "2026-09-19T08:00:00Z",
  "event_type": "login_failure",
  "source_ip": "203.0.113.10",
  "username": "alex",
  "message": "Invalid password"
}
```

HTTP event example:

```json
{
  "timestamp": "2026-09-19T09:00:00Z",
  "event_type": "http_request",
  "source_ip": "198.51.100.20",
  "message": "GET /api/orders",
  "status_code": 503,
  "metadata": {
    "service": "orders-api"
  }
}
```

## Configuration

Environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `LOGSCOPE_DB` | `./data/logscope.db` | SQLite database path |
| `LOGSCOPE_FAILURE_THRESHOLD` | `5` | Detection threshold |
| `LOGSCOPE_WINDOW_MINUTES` | `10` | Detection time window |

## Quality checks

Run the same checks used by CI:

```bash
ruff check src tests
mypy src
pytest --cov=logscope --cov-report=term-missing
python -m build
```

## Docker

Build:

```bash
docker build -t logscope .
```

Analyze a mounted input file:

```bash
docker run --rm \
  -v "${PWD}/examples:/app/examples:ro" \
  -v "${PWD}/data:/app/data" \
  logscope ingest /app/examples/sample-events.jsonl
```

Then run:

```bash
docker run --rm -v "${PWD}/data:/app/data" logscope analyze
```

## Why this is useful in a portfolio

LogScope demonstrates Python in several roles at once:

- **application development** through packaging and CLI design;
- **data engineering** through parsing and normalization;
- **backend fundamentals** through persistent storage and indexing;
- **cybersecurity/operations** through defensive event analysis;
- **software quality** through linting, typing, automated tests, and coverage;
- **DevOps fundamentals** through Docker and GitHub Actions.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design.
