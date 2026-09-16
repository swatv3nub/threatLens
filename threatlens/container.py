from __future__ import annotations

from functools import lru_cache

from threatlens.agents.policies import PolicyEngine
from threatlens.agents.triage_agent import TriageAgent
from threatlens.config import Settings, get_settings
from threatlens.enrichment.abuseipdb import AbuseIPDBTool
from threatlens.enrichment.asset_context import AssetContextTool
from threatlens.enrichment.engine import EnrichmentEngine
from threatlens.enrichment.history import AlertHistoryTool
from threatlens.enrichment.mitre import MitreLookupTool
from threatlens.enrichment.registry import ToolRegistry
from threatlens.enrichment.virustotal import VirusTotalTool
from threatlens.llm.factory import build_llm_provider
from threatlens.observability.logging import configure_logging
from threatlens.observability.metrics import METRICS
from threatlens.observability.otel import configure_telemetry, get_metrics_bridge
from threatlens.reasoning.confidence import ConfidenceCalculator
from threatlens.reasoning.engine import ReasoningEngine
from threatlens.security.allowlist import Allowlist
from threatlens.security.audit import AuditLog
from threatlens.security.rate_limiter import (
    RateLimiter,
    RedisRateLimiter,
    SlidingWindowRateLimiter,
    ToolBudget,
)
from threatlens.storage.database import Database
from threatlens.storage.repositories import UnitOfWork


class Container:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        configure_logging(self.settings.log_level)
        configure_telemetry(self.settings)
        metrics_bridge = get_metrics_bridge()
        if metrics_bridge is not None:
            METRICS.configure_exporter(metrics_bridge)
        self.database = Database(self.settings.database_url)
        if self.settings.database_auto_create:
            self.database.create_all()
        self.uow = UnitOfWork(self.database)
        self.allowlist = Allowlist.from_settings(self.settings)
        self.audit = AuditLog(persist=self._persist_audit_event)
        self.registry = ToolRegistry(
            max_retries=self.settings.max_tool_retries,
            timeout_seconds=self.settings.tool_timeout_seconds,
            audit=self.audit,
            persist_tool_call=self._persist_tool_call,
        )
        self._register_tools()
        self.budget = ToolBudget(self.settings.max_tool_calls)
        self.enrichment = EnrichmentEngine(self.registry, self.budget)
        self.llm = build_llm_provider(self.settings, self.allowlist)
        self.reasoning = ReasoningEngine(
            self.llm, ConfidenceCalculator()
        )
        self.policies = PolicyEngine()
        self.agent = TriageAgent(
            enrichment=self.enrichment,
            reasoning=self.reasoning,
            policies=self.policies,
            audit=self.audit,
        )
        if self.settings.rate_limit_backend == "redis":
            if self.settings.redis_url is None:
                raise ValueError("REDIS_URL is required for Redis rate limiting")
            self.api_rate_limiter: RateLimiter = RedisRateLimiter(
                url=self.settings.redis_url, limit=self.settings.rate_limit_per_minute
            )
        else:
            self.api_rate_limiter = SlidingWindowRateLimiter(
                limit=self.settings.rate_limit_per_minute
            )

    def _register_tools(self) -> None:
        self.registry.register(VirusTotalTool(self.settings, self.allowlist))
        self.registry.register(AbuseIPDBTool(self.settings, self.allowlist))
        self.registry.register(
            AssetContextTool(repository=self.uow.assets)
        )
        self.registry.register(AlertHistoryTool(repository=self.uow.alerts))
        self.registry.register(MitreLookupTool())

    def _persist_tool_call(self, call: object, context: object) -> None:
        from threatlens.enrichment.base import ToolCall, ToolContext

        if not isinstance(call, ToolCall) or not isinstance(context, ToolContext):
            return
        self.uow.tool_calls.save(
            call_id=call.call_id,
            agent_run_id=context.agent_run_id or "unknown",
            alert_id=context.alert.id,
            tool_name=call.tool_name,
            arguments=call.arguments,
            success=call.success,
            latency_ms=call.latency_ms,
            result_summary=call.result_summary,
        )

    def _persist_audit_event(self, event: object) -> None:
        from threatlens.security.audit import AuditEvent

        if not isinstance(event, AuditEvent):
            return
        self.uow.audit.save(event)
        self.uow.ledger.save(event)


@lru_cache(maxsize=1)
def get_container() -> Container:
    return Container()


def create_container(settings: Settings | None = None) -> Container:
    """Build an isolated dependency container for an app or test instance."""
    return Container(settings=settings)


def reset_container() -> None:
    get_container.cache_clear()
