from __future__ import annotations

import pytest

from threatlens.models.alerts import NormalizedAlert
from threatlens.models.triage import TriageResult
from threatlens.reports.renderer import ReportError, ReportRenderer


@pytest.fixture()
def sample_alert() -> NormalizedAlert:
    return NormalizedAlert(
        source="synthetic",
        rule_name="Test Rule",
        severity="high",
        hostname="test-host",
        destination_ip="203.0.113.66",
    )


@pytest.fixture()
def sample_triage(sample_alert: NormalizedAlert) -> TriageResult:
    return TriageResult(
        triage_id="test-triage-001",
        alert_id=sample_alert.id,
        agent_run_id="test-run-001",
        classification="true_positive",
        severity="high",
        model_confidence=0.85,
        confidence=0.78,
        summary="Test summary",
        evidence=[],
        recommended_actions=[],
        mitre_attack=["T1071.001 Web Protocols"],
        uncertainties=["Test uncertainty"],
        requires_human_review=True,
        action_executed="none",
        policy_adjustments=["Test adjustment"],
        tool_call_count=3,
    )


def test_render_html(sample_alert: NormalizedAlert, sample_triage: TriageResult) -> None:
    renderer = ReportRenderer()
    html = renderer.render_html(alert=sample_alert, triage=sample_triage)
    assert "ThreatLens Analysis Report" in html
    assert "test-triage-001" in html
    assert "TRUE POSITIVE" in html  # template uses uppercased with space
    assert "HIGH" in html  # template uses uppercased severity
    assert "Test summary" in html
    assert "T1071.001 Web Protocols" in html


def test_render_html_with_audit_and_tools(
    sample_alert: NormalizedAlert, sample_triage: TriageResult
) -> None:
    from types import SimpleNamespace

    from threatlens.security.audit import AuditEvent

    renderer = ReportRenderer()
    audit = [AuditEvent(event_type="tool_call", detail={"tool": "virustotal"})]
    tool_calls = [SimpleNamespace(tool_name="virustotal", success=True, latency_ms=10.5)]
    html = renderer.render_html(
        alert=sample_alert,
        triage=sample_triage,
        audit_events=audit,
        tool_calls=tool_calls,
    )
    assert "virustotal" in html
    assert "tool_call" in html


def test_render_pdf_raises_without_weasyprint(
    sample_alert: NormalizedAlert, sample_triage: TriageResult, tmp_path
) -> None:
    # WeasyPrint may not have system deps on Windows; expect clear error or skip
    renderer = ReportRenderer()
    try:
        renderer.render_pdf(
            alert=sample_alert, triage=sample_triage, output_dir=tmp_path
        )
    except (ReportError, RuntimeError, OSError) as e:
        # Acceptable: WeasyPrint not available or missing system libs
        assert "WeasyPrint" in str(e) or "library" in str(e).lower() or "libgobject" in str(e)
    else:
        # If it works, great - PDF was generated
        pass
