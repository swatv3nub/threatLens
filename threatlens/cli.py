from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from threatlens.config import get_settings
from threatlens.container import create_container, get_container
from threatlens.evaluation.runner import EvaluationRunner
from threatlens.ingestion.base import get_ingestor
from threatlens.ingestion.synthetic import load_synthetic, write_scenarios
from threatlens.models.alerts import AlertSource, NormalizedAlert
from threatlens.reports.renderer import ReportError, ReportRenderer, render_triage_pdf

app = typer.Typer(
    name="threatlens",
    help="Agentic security alert triage platform",
    no_args_is_help=True,
)
console = Console()


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise typer.BadParameter(f"{path}: expected a JSON object at the top level")
    return data


def _detect_source(data: dict[str, Any]) -> AlertSource:
    """Best-effort source detection for zero-flag CLI usage."""
    if isinstance(data.get("_source"), dict) or data.get("_index"):
        return AlertSource.elastic
    if "event_type" in data and isinstance(data.get("alert"), dict):
        return AlertSource.suricata
    if isinstance(data.get("rule"), dict) and (
        "agent" in data or "decoder" in data or "id" in data["rule"]
    ):
        return AlertSource.wazuh
    raw_source = data.get("source")
    if isinstance(raw_source, str):
        try:
            return AlertSource(raw_source)
        except ValueError:
            pass
    return AlertSource.synthetic


def _parse_file(path: Path, source: str | None) -> NormalizedAlert:
    data = _read_json(path)
    if source is None:
        detected = _detect_source(data)
    else:
        try:
            detected = AlertSource(source)
        except ValueError as exc:
            raise typer.BadParameter(
                f"unknown source {source!r}; "
                f"choose from {[s.value for s in AlertSource]}"
            ) from exc
    return get_ingestor(detected).parse(data)


@app.command()
def ingest(
    path: Path = typer.Argument(..., exists=True, readable=True),
    source: str | None = typer.Option(None, "--source", "-s"),
) -> None:
    container = get_container()
    alert = _parse_file(path, source)
    container.uow.alerts.save(alert)
    console.print(
        Panel.fit(
            f"Ingested [bold]{alert.id}[/bold]\nsource={alert.source.value}\n"
            f"rule={alert.rule_name}\nseverity={alert.severity.value}",
            title="Alert ingested",
        )
    )


@app.command()
def triage(
    path: Path = typer.Argument(..., exists=True, readable=True),
    source: str | None = typer.Option(None, "--source", "-s"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON instead of the note"),
) -> None:
    container = get_container()
    alert = _parse_file(path, source)
    container.uow.alerts.save(alert)
    result = asyncio.run(container.agent.run(alert))
    container.uow.triage.save(result)
    if json_out:
        console.print_json(result.model_dump_json())
    else:
        console.print(result.to_analyst_note())


@app.command()
def report(
    triage_id: str = typer.Argument(...),
    output_dir: Path = typer.Option(Path("reports_output"), "--out", "-o"),
    report_format: Literal["pdf", "html"] = typer.Option("pdf", "--format"),
) -> None:
    container = get_container()
    triage_result = container.uow.triage.get(triage_id)
    if triage_result is None:
        console.print(f"[red]triage {triage_id} not found[/red]")
        raise typer.Exit(code=1)
    alert = container.uow.alerts.get(triage_result.alert_id)
    if alert is None:
        console.print(f"[red]alert {triage_result.alert_id} not found[/red]")
        raise typer.Exit(code=1)
    audit_events = container.uow.audit.for_alert(alert.id)
    tool_calls = container.uow.tool_calls.for_alert(alert.id)
    renderer = ReportRenderer()
    output_dir.mkdir(parents=True, exist_ok=True)
    if report_format == "html":
        html_path = output_dir / f"{triage_result.triage_id}.html"
        html_path.write_text(
            renderer.render_html(
                alert=alert,
                triage=triage_result,
                audit_events=audit_events,
                tool_calls=tool_calls,
            ),
            encoding="utf-8",
        )
        console.print(f"[green]HTML report written:[/green] {html_path}")
        return
    try:
        pdf = render_triage_pdf(
            alert=alert,
            triage=triage_result,
            output_dir=output_dir,
            audit_events=audit_events,
            tool_calls=tool_calls,
        )
    except ReportError as exc:
        html_path = output_dir / f"{triage_result.triage_id}.html"
        html_path.write_text(
            renderer.render_html(
                alert=alert,
                triage=triage_result,
                audit_events=audit_events,
                tool_calls=tool_calls,
            ),
            encoding="utf-8",
        )
        console.print(f"[yellow]{exc}[/yellow]")
        console.print(f"[green]HTML report written:[/green] {html_path}")
        return
    console.print(f"[green]PDF written:[/green] {pdf}")


@app.command()
def replay(
    directory: Path = typer.Argument(..., exists=True, file_okay=False),
) -> None:
    container = get_container()
    files = sorted(Path(directory).glob("*.json"))
    if not files:
        console.print("[yellow]no JSON alerts found[/yellow]")
        raise typer.Exit(code=1)
    table = Table(title=f"Replay: {len(files)} alerts")
    table.add_column("Alert")
    table.add_column("Classification")
    table.add_column("Severity")
    table.add_column("Confidence")
    for f in files:
        alert = load_synthetic(f)
        container.uow.alerts.save(alert)
        result = asyncio.run(container.agent.run(alert))
        container.uow.triage.save(result)
        table.add_row(
            f.name,
            result.classification.value,
            result.severity.value,
            f"{result.confidence:.0%}",
        )
    console.print(table)


@app.command()
def evaluate(
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    # Benchmarks must not inherit historical alerts from the application database.
    settings = get_settings()
    with TemporaryDirectory(prefix="threatlens-eval-") as temp_dir:
        eval_settings = settings.model_copy(
            update={
                "database_url": f"sqlite:///{Path(temp_dir, 'evaluation.db').as_posix()}"
            }
        )
        container = create_container(eval_settings)
        try:
            runner = EvaluationRunner(container.agent)
            report_result = asyncio.run(runner.run())
        finally:
            container.database.dispose()
    console.print(report_result.render())
    if output:
        payload = [
            {
                "case_id": r.case_id,
                "expected_classification": r.expected_classification.value,
                "actual_classification": r.actual_classification.value,
                "expected_severity": r.expected_severity,
                "actual_severity": r.actual_severity,
                "confidence": r.confidence,
                "evidence_count": r.evidence_count,
                "tool_calls": r.tool_calls,
                "latency_ms": r.latency_ms,
                "errors": r.errors,
            }
            for r in report_result.results
        ]
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[green]Results written:[/green] {output}")


@app.command()
def backup(
    output: Path | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Create a consistent backup of the configured SQLite database."""
    container = get_container()
    target = output or Path(container.settings.backup_dir) / (
        f"threatlens-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.db"
    )
    try:
        path = container.database.backup(target)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    cutoff = datetime.now(UTC).timestamp() - (container.settings.retention_days * 86400)
    for old_backup in path.parent.glob("threatlens-*.db"):
        if old_backup != path and old_backup.stat().st_mtime < cutoff:
            old_backup.unlink()
    console.print(f"[green]Database backup written:[/green] {path}")


@app.command()
def scenarios(
    directory: Path = typer.Option(Path("samples/synthetic"), "--out", "-o"),
) -> None:
    paths = write_scenarios(directory)
    console.print(f"[green]Wrote {len(paths)} synthetic scenarios to {directory}[/green]")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    import uvicorn

    uvicorn.run("threatlens.api.app:app", host=host, port=port)


if __name__ == "__main__":
    app()
