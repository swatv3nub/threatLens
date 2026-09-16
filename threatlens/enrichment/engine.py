from __future__ import annotations

from threatlens.enrichment.base import ToolContext, ToolResult
from threatlens.enrichment.registry import ToolRegistry
from threatlens.models.alerts import NormalizedAlert
from threatlens.models.enrichment import (
    AssetContext,
    DomainReputation,
    EnrichmentContext,
    FileReputation,
    HistoricalContext,
    IPReputation,
    MitreTechnique,
    URLReputation,
)
from threatlens.observability.logging import get_logger, log_event
from threatlens.security.rate_limiter import ToolBudget

logger = get_logger("threatlens.enrichment")


class EnrichmentEngine:
    """Selects applicable tools, executes them, and aggregates structured results."""

    def __init__(self, registry: ToolRegistry, budget: ToolBudget) -> None:
        self._registry = registry
        self._budget = budget

    def set_budget(self, budget: ToolBudget) -> None:
        self._budget = budget

    @property
    def max_tool_calls(self) -> int:
        return self._budget.max_calls

    def select_tools(self, alert: NormalizedAlert) -> list[str]:
        applicable = self._registry.applicable_tools(alert)
        return [t.name for t in applicable]

    async def run(
        self, alert: NormalizedAlert, *, agent_run_id: str | None = None
    ) -> tuple[EnrichmentContext, list[ToolResult]]:
        context = ToolContext(alert=alert, agent_run_id=agent_run_id)
        selected = self.select_tools(alert)
        log_event(logger, "enrichment_start", alert_id=alert.id, tools=selected)
        results: list[ToolResult] = []
        aggregated = EnrichmentContext()
        for name in selected:
            result, _call = await self._registry.invoke(name, context, budget=self._budget)
            results.append(result)
            if result.ok:
                self._merge(aggregated, result)
            else:
                aggregated.tool_errors.append(
                    f"{name}: {result.error or result.status.value}"
                )
                aggregated.degraded = True
        log_event(
            logger,
            "enrichment_complete",
            alert_id=alert.id,
            degraded=aggregated.degraded,
            errors=len(aggregated.tool_errors),
        )
        return aggregated, results

    @staticmethod
    def _merge(ctx: EnrichmentContext, result: ToolResult) -> None:
        data = result.data
        if result.tool_name in {"virustotal", "abuseipdb"}:
            for key, value in data.items():
                if not isinstance(value, dict):
                    continue
                if key.startswith("ip:") or "confidence_score" in value:
                    try:
                        ctx.ip_reputations.append(IPReputation(**value))
                    except (TypeError, ValueError):
                        logger.debug("discarded malformed IP reputation")
                elif key.startswith("domain:"):
                    try:
                        ctx.domain_reputations.append(DomainReputation(**value))
                    except (TypeError, ValueError):
                        logger.debug("discarded malformed domain reputation")
                elif key.startswith("file:"):
                    try:
                        ctx.file_reputations.append(FileReputation(**value))
                    except (TypeError, ValueError):
                        logger.debug("discarded malformed file reputation")
                elif key.startswith("url:"):
                    try:
                        ctx.url_reputations.append(URLReputation(**value))
                    except (TypeError, ValueError):
                        logger.debug("discarded malformed URL reputation")
        elif result.tool_name == "asset_context":
            if data.get("found"):
                try:
                    ctx.assets.append(AssetContext(**data))
                except Exception:
                    ctx.missing_context.append("asset record malformed")
            else:
                ctx.missing_context.append(data.get("missing_context", "asset not found"))
        elif result.tool_name == "alert_history":
            for query in data.get("queries", []):
                if not isinstance(query, dict):
                    continue
                ctx.history.append(
                    HistoricalContext(
                        query=query.get("query", ""),
                        window_hours=int(query.get("window_hours", 24)),
                        matches=[],
                        count=int(query.get("count", 0)),
                    )
                )
            if data.get("missing_context"):
                ctx.missing_context.append(str(data["missing_context"]))
        elif result.tool_name == "mitre_attack":
            for tech in data.get("techniques", []):
                try:
                    ctx.mitre_techniques.append(MitreTechnique(**tech))
                except (TypeError, ValueError):
                    logger.debug("discarded malformed MITRE technique")
