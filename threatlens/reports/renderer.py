from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from threatlens.models.alerts import NormalizedAlert
from threatlens.models.triage import TriageResult
from threatlens.security.audit import AuditEvent

TEMPLATE_DIR = Path(__file__).parent / "templates"
TEMPLATE_NAME = "triage_report.html.j2"


class ReportError(RuntimeError):
    pass


def _environment(template_dir: Path | None = None) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(template_dir or TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


class ReportRenderer:
    """Renders the analyst-facing triage report to HTML and PDF.

    HTML rendering has no heavy dependencies. PDF rendering requires WeasyPrint,
    which is optional; a clear error is raised when it is unavailable so the CLI
    can degrade gracefully.
    """

    def __init__(self, template_dir: Path | None = None) -> None:
        self._env = _environment(template_dir)

    def render_html(
        self,
        *,
        alert: NormalizedAlert,
        triage: TriageResult,
        audit_events: Sequence[AuditEvent | Mapping[str, object]] | None = None,
        tool_calls: Sequence[Any] | None = None,
    ) -> str:
        template = self._env.get_template(TEMPLATE_NAME)
        return template.render(
            alert=alert,
            triage=triage,
            audit_events=[self._audit_view(e) for e in (audit_events or [])],
            tool_calls=[self._tool_view(c) for c in (tool_calls or [])],
        )

    def render_pdf(
        self,
        *,
        alert: NormalizedAlert,
        triage: TriageResult,
        output_dir: Path | str,
        audit_events: Sequence[AuditEvent | Mapping[str, object]] | None = None,
        tool_calls: Sequence[Any] | None = None,
    ) -> Path:
        html = self.render_html(
            alert=alert, triage=triage, audit_events=audit_events, tool_calls=tool_calls
        )
        weasyprint = _import_weasyprint()
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{_safe_filename(triage.triage_id)}.pdf"
        try:
            weasyprint.HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf(str(out_path))
        except (OSError, RuntimeError) as exc:
            raise ReportError(
                "PDF rendering is unavailable on this system; use the HTML report instead"
            ) from exc
        return out_path

    @staticmethod
    def _audit_view(event: AuditEvent | Mapping[str, object]) -> dict[str, object]:
        if isinstance(event, AuditEvent):
            return {
                "timestamp": event.timestamp.isoformat(timespec="seconds"),
                "event_type": event.event_type,
                "detail": event.redacted_detail(),
            }
        timestamp = event.get("timestamp", "")
        return {
            "timestamp": str(timestamp),
            "event_type": str(event.get("event_type", "")),
            "detail": event.get("detail", {}),
        }

    @staticmethod
    def _tool_view(call: Any) -> dict[str, object]:
        success = bool(getattr(call, "success", getattr(call, "ok", False)))
        return {
            "tool_name": getattr(call, "tool_name", "unknown"),
            "success": success,
            "latency_ms": float(getattr(call, "latency_ms", 0.0)),
            "result_summary": getattr(
                call, "result_summary", getattr(call, "summary", None)
            ),
            "error": getattr(call, "error", None),
        }


def _safe_filename(value: str) -> str:
    """Reject path traversal: keep only a conservative identifier charset."""
    cleaned = "".join(c for c in value if c.isalnum() or c in "-_.")
    cleaned = cleaned.strip(".")
    if not cleaned:
        raise ReportError("invalid triage id for report filename")
    return cleaned


def _import_weasyprint() -> Any:
    try:
        import weasyprint
    except (ImportError, OSError, RuntimeError) as exc:  # pragma: no cover
        raise ReportError(
            "WeasyPrint is not installed. Install the 'pdf' extra: "
            "pip install -e '.[pdf]'"
        ) from exc
    return weasyprint


def render_triage_pdf(
    *,
    alert: NormalizedAlert,
    triage: TriageResult,
    output_dir: Path | str = "reports_output",
    audit_events: Sequence[AuditEvent | Mapping[str, object]] | None = None,
    tool_calls: Sequence[Any] | None = None,
) -> Path:
    return ReportRenderer().render_pdf(
        alert=alert,
        triage=triage,
        output_dir=output_dir,
        audit_events=audit_events,
        tool_calls=tool_calls,
    )


__all__ = ["ReportError", "ReportRenderer", "render_triage_pdf"]
