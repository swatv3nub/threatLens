from __future__ import annotations

import pytest

from threatlens.container import Container
from threatlens.enrichment.base import ToolContext
from threatlens.models.alerts import NormalizedAlert
from threatlens.security.rate_limiter import ToolBudget


def test_container_persists_audit_events(settings) -> None:
    container = Container(settings)
    alert = NormalizedAlert(source="synthetic", severity="low")

    container.audit.emit("test_event", alert_id=alert.id, detail={"safe": True})

    events = container.uow.audit.for_alert(alert.id)
    assert len(events) == 1
    assert events[0]["event_type"] == "test_event"


@pytest.mark.asyncio
async def test_registry_persists_tool_calls(settings) -> None:
    container = Container(settings)
    alert = NormalizedAlert(source="synthetic", severity="low")
    context = ToolContext(alert=alert, agent_run_id="run-1")

    await container.registry.invoke(
        "mitre_attack",
        context,
        budget=ToolBudget(1),
    )

    calls = container.uow.tool_calls.for_alert(alert.id)
    assert len(calls) == 1
    assert calls[0]["tool_name"] == "mitre_attack"
    assert calls[0]["success"] is True


@pytest.mark.asyncio
async def test_triage_persists_ordered_investigation_ledger(settings) -> None:
    container = Container(settings)
    alert = NormalizedAlert(source="synthetic", severity="low")
    result = await container.agent.run(alert)

    entries = container.uow.ledger.for_triage(result.triage_id)

    assert entries
    assert [entry["sequence"] for entry in entries] == list(range(1, len(entries) + 1))
    assert entries[0]["step_type"] == "investigation_started"
    assert entries[-1]["step_type"] == "triage_completed"
