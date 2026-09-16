from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol, runtime_checkable
from uuid import uuid4

from pydantic import BaseModel, Field

from threatlens.models.alerts import NormalizedAlert


class ToolStatus(str, Enum):
    success = "success"
    failure = "failure"
    skipped = "skipped"
    rate_limited = "rate_limited"
    timeout = "timeout"


class ToolContext(BaseModel):
    alert: NormalizedAlert
    request_id: str | None = None
    agent_run_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    tool_name: str
    status: ToolStatus = ToolStatus.success
    data: dict[str, Any] = Field(default_factory=dict)
    summary: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    error: str | None = None
    latency_ms: float = 0.0
    call_id: str = Field(default_factory=lambda: str(uuid4()))

    @property
    def ok(self) -> bool:
        return self.status == ToolStatus.success


class ToolCall(BaseModel):
    call_id: str = Field(default_factory=lambda: str(uuid4()))
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    latency_ms: float = 0.0
    success: bool = True
    result_summary: str | None = None
    error: str | None = None
    correlation_id: str | None = None


@runtime_checkable
class EnrichmentTool(Protocol):
    name: str

    def is_applicable(self, alert: NormalizedAlert) -> bool: ...

    async def execute(self, context: ToolContext) -> ToolResult: ...


class BaseTool:
    name: str = "base"
    reliability: float = 0.8

    def is_applicable(self, alert: NormalizedAlert) -> bool:
        return True

    async def execute(self, context: ToolContext) -> ToolResult:
        raise NotImplementedError
