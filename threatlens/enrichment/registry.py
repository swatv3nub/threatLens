from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any

from threatlens.enrichment.base import (
    EnrichmentTool,
    ToolCall,
    ToolContext,
    ToolResult,
    ToolStatus,
)
from threatlens.observability.logging import get_logger, log_event
from threatlens.observability.metrics import METRICS
from threatlens.security.audit import AuditLog
from threatlens.security.rate_limiter import RateLimitExceeded, ToolBudget

logger = get_logger("threatlens.tools")


class ToolNotRegisteredError(ValueError):
    pass


class ToolRegistry:
    """Allowlisted tool registry. Only registered tools may ever be invoked."""

    def __init__(
        self,
        *,
        max_retries: int = 3,
        timeout_seconds: float = 10.0,
        audit: AuditLog | None = None,
        persist_tool_call: Callable[[ToolCall, ToolContext], None] | None = None,
    ) -> None:
        self._tools: dict[str, EnrichmentTool] = {}
        self._max_retries = max_retries
        self._timeout = timeout_seconds
        self._audit = audit or AuditLog()
        self._persist_tool_call = persist_tool_call

    def _persist_call(self, call: ToolCall, context: ToolContext) -> None:
        if self._persist_tool_call is not None:
            self._persist_tool_call(call, context)

    def register(self, tool: EnrichmentTool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> EnrichmentTool:
        if name not in self._tools:
            raise ToolNotRegisteredError(f"tool not registered: {name!r}")
        return self._tools[name]

    def names(self) -> list[str]:
        return sorted(self._tools)

    def applicable_tools(self, alert: Any) -> list[EnrichmentTool]:
        return [t for t in self._tools.values() if t.is_applicable(alert)]

    async def invoke(
        self,
        name: str,
        context: ToolContext,
        *,
        budget: ToolBudget,
        arguments: dict[str, Any] | None = None,
    ) -> tuple[ToolResult, ToolCall]:
        tool = self.get(name)
        call = ToolCall(
            tool_name=name,
            arguments=arguments or {},
            correlation_id=context.request_id,
        )
        try:
            budget.consume()
        except RateLimitExceeded as exc:
            call.success = False
            call.error = str(exc)
            result = ToolResult(
                tool_name=name, status=ToolStatus.rate_limited, error=str(exc)
            )
            self._audit.emit(
                "tool_call_rejected",
                alert_id=context.alert.id,
                agent_run_id=context.agent_run_id,
                detail={"tool": name, "reason": str(exc)},
            )
            self._persist_call(call, context)
            return result, call

        last_error: str | None = None
        for attempt in range(1, self._max_retries + 1):
            start = time.monotonic()
            try:
                result = await asyncio.wait_for(
                    tool.execute(context), timeout=self._timeout
                )
                call.latency_ms = (time.monotonic() - start) * 1000.0
                result.latency_ms = call.latency_ms
                call.success = result.ok
                call.result_summary = result.summary
                METRICS.increment("tool_calls_total")
                METRICS.observe("tool_latency_seconds", call.latency_ms / 1000.0)
                if not result.ok:
                    METRICS.increment("tool_errors_total")
                log_event(
                    logger,
                    "tool_call",
                    tool=name,
                    success=result.ok,
                    latency_ms=round(call.latency_ms, 2),
                    attempt=attempt,
                )
                self._audit.emit(
                    "tool_call",
                    alert_id=context.alert.id,
                    agent_run_id=context.agent_run_id,
                    detail={
                        "tool": name,
                        "success": result.ok,
                        "latency_ms": round(call.latency_ms, 2),
                        "summary": result.summary,
                    },
                )
                self._persist_call(call, context)
                return result, call
            except TimeoutError:
                last_error = f"tool {name!r} timed out after {self._timeout}s"
                METRICS.increment("tool_timeouts_total")
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            if attempt < self._max_retries:
                await asyncio.sleep(min(2 ** (attempt - 1) * 0.1, 1.0))

        call.success = False
        call.error = last_error
        METRICS.increment("tool_errors_total")
        log_event(logger, "tool_call_failed", tool=name, error=last_error)
        self._persist_call(call, context)
        return (
            ToolResult(tool_name=name, status=ToolStatus.failure, error=last_error),
            call,
        )
