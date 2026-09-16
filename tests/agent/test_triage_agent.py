from __future__ import annotations

import pytest

from threatlens.agents.triage_agent import TriageAgent
from threatlens.enrichment.abuseipdb import AbuseIPDBTool
from threatlens.enrichment.asset_context import AssetContextTool
from threatlens.enrichment.engine import EnrichmentEngine
from threatlens.enrichment.history import AlertHistoryTool
from threatlens.enrichment.mitre import MitreLookupTool
from threatlens.enrichment.registry import ToolRegistry
from threatlens.enrichment.virustotal import VirusTotalTool
from threatlens.llm.mock import MockLLMProvider
from threatlens.models.alerts import NormalizedAlert
from threatlens.models.reasoning import Classification
from threatlens.reasoning.engine import ReasoningEngine
from threatlens.security.allowlist import Allowlist
from threatlens.security.rate_limiter import ToolBudget
from threatlens.storage.database import Database
from threatlens.storage.repositories import UnitOfWork


@pytest.fixture()
def agent(settings) -> TriageAgent:
    allowlist = Allowlist.from_settings(settings)
    db = Database(settings.database_url)
    db.create_all()
    uow = UnitOfWork(db)
    registry = ToolRegistry(max_retries=1, timeout_seconds=2.0)
    registry.register(VirusTotalTool(settings, allowlist))
    registry.register(AbuseIPDBTool(settings, allowlist))
    registry.register(AssetContextTool(repository=uow.assets))
    registry.register(AlertHistoryTool(repository=uow.alerts))
    registry.register(MitreLookupTool())
    enrichment = EnrichmentEngine(registry, ToolBudget(settings.max_tool_calls))
    reasoning = ReasoningEngine(MockLLMProvider())
    return TriageAgent(enrichment=enrichment, reasoning=reasoning)


async def test_malicious_ip_critical_asset_is_true_positive(agent: TriageAgent) -> None:
    alert = NormalizedAlert(
        source="synthetic",
        severity="high",
        hostname="payments-prod-01",
        source_ip="10.1.20.15",
        destination_ip="203.0.113.66",
        destination_port=8443,
        category="command_and_control",
    )
    result = await agent.run(alert)
    assert result.classification == Classification.true_positive
    assert result.severity.value in {"high", "critical"}
    assert result.confidence > 0.5
    assert result.evidence
    assert result.action_executed == "none"
    assert result.requires_human_review is True


async def test_benign_scanner_is_not_true_positive(agent: TriageAgent) -> None:
    alert = NormalizedAlert(
        source="synthetic",
        severity="low",
        hostname="scan-runner-01",
        source_ip="192.0.2.50",
        destination_ip="10.1.10.10",
        category="scanning",
    )
    result = await agent.run(alert)
    assert result.classification in {
        Classification.false_positive,
        Classification.benign,
        Classification.needs_investigation,
    }
    assert result.severity.value in {"low", "informational", "medium"}


async def test_malicious_hash_forces_high_minimum(agent: TriageAgent) -> None:
    alert = NormalizedAlert(
        source="synthetic",
        severity="medium",
        hostname="fileserver-02",
        file_hash="44d88612fea8a8f36de82e1278abb02f" + "0" * 32,
    )
    result = await agent.run(alert)
    assert result.severity.value in {"high", "critical"}
    assert result.classification == Classification.true_positive


async def test_missing_asset_reports_uncertainty(agent: TriageAgent) -> None:
    alert = NormalizedAlert(
        source="synthetic",
        severity="medium",
        hostname="unknown-host-xyz",
    )
    result = await agent.run(alert)
    assert result.requires_human_review is True


async def test_agent_never_executes_actions(agent: TriageAgent) -> None:
    alert = NormalizedAlert(
        source="synthetic",
        severity="critical",
        hostname="payments-prod-01",
        destination_ip="203.0.113.66",
        file_hash="44d88612fea8a8f36de82e1278abb02f" + "0" * 32,
    )
    result = await agent.run(alert)
    assert result.action_executed == "none"
    for action in result.recommended_actions:
        assert action.requires_human_approval is True
