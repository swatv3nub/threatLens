from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel

from threatlens.agents.triage_agent import TriageAgent
from threatlens.enrichment.base import BaseTool, ToolContext, ToolResult
from threatlens.enrichment.engine import EnrichmentEngine
from threatlens.enrichment.registry import ToolRegistry
from threatlens.llm.base import LLMError, LLMProvider
from threatlens.models.alerts import NormalizedAlert
from threatlens.models.enrichment import IPReputation
from threatlens.models.reasoning import Classification
from threatlens.reasoning.engine import ReasoningEngine, deterministic_fallback
from threatlens.security.rate_limiter import ToolBudget

T = TypeVar("T", bound=BaseModel)


class FailingTool(BaseTool):
    name = "failing"

    def is_applicable(self, alert: NormalizedAlert) -> bool:
        return True

    async def execute(self, context: ToolContext) -> ToolResult:
        raise RuntimeError("simulated provider outage")


class MalformedLLM:
    name = "malformed"

    async def generate_structured(
        self, *, system_prompt: str, input_data: dict[str, Any], response_model: type[T]
    ) -> T:
        raise LLMError("schema validation failed")


class UnavailableLLM:
    name = "unavailable"

    async def generate_structured(
        self, *, system_prompt: str, input_data: dict[str, Any], response_model: type[T]
    ) -> T:
        raise LLMError("provider unavailable")


def _agent_with(registry: ToolRegistry, provider: LLMProvider) -> TriageAgent:
    enrichment = EnrichmentEngine(registry, ToolBudget(5))
    reasoning = ReasoningEngine(provider)
    return TriageAgent(enrichment=enrichment, reasoning=reasoning)


async def test_tool_failure_degrades_gracefully(settings) -> None:
    registry = ToolRegistry(max_retries=1, timeout_seconds=1.0)
    registry.register(FailingTool())
    from threatlens.llm.mock import MockLLMProvider

    agent = _agent_with(registry, MockLLMProvider())
    alert = NormalizedAlert(source="synthetic", severity="medium", hostname="host-1")
    result = await agent.run(alert)
    assert result.triage_id
    assert result.requires_human_review is True


async def test_malformed_llm_output_falls_back_to_deterministic(settings) -> None:
    registry = ToolRegistry(max_retries=1, timeout_seconds=1.0)
    agent = _agent_with(registry, MalformedLLM())
    alert = NormalizedAlert(source="synthetic", severity="high", hostname="host-1")
    result = await agent.run(alert)
    assert result.classification == Classification.needs_investigation


async def test_llm_unavailable_falls_back(settings) -> None:
    registry = ToolRegistry(max_retries=1, timeout_seconds=1.0)
    agent = _agent_with(registry, UnavailableLLM())
    alert = NormalizedAlert(source="synthetic", severity="critical", hostname="host-1")
    result = await agent.run(alert)
    assert result.classification == Classification.needs_investigation
    assert result.confidence <= 0.5


async def test_tool_budget_exhaustion_is_safe(settings) -> None:
    registry = ToolRegistry(max_retries=1, timeout_seconds=1.0)
    registry.register(FailingTool())
    from threatlens.llm.mock import MockLLMProvider

    enrichment = EnrichmentEngine(registry, ToolBudget(0))
    reasoning = ReasoningEngine(MockLLMProvider())
    agent = TriageAgent(enrichment=enrichment, reasoning=reasoning)
    alert = NormalizedAlert(source="synthetic", severity="medium", hostname="host-1")
    result = await agent.run(alert)
    assert result.triage_id


def test_deterministic_fallback_shape() -> None:
    alert = NormalizedAlert(source="synthetic", severity="high")
    fallback = deterministic_fallback(alert)
    assert fallback.classification == Classification.needs_investigation
    assert fallback.uncertainties


def test_contradictory_enrichment_detected() -> None:
    from threatlens.models.enrichment import EnrichmentContext
    from threatlens.reasoning.engine import ReasoningEngine as RE

    ctx = EnrichmentContext(
        ip_reputations=[
            IPReputation(ip="203.0.113.66", malicious=True),
            IPReputation(ip="10.0.0.1", malicious=False),
        ]
    )
    assert RE._detect_contradiction(ctx) is True
