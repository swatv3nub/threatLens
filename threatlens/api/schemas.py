from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from threatlens.models.alerts import AlertSource, NormalizedAlert, Severity
from threatlens.models.reasoning import Classification, RecommendedAction


class AlertSubmission(BaseModel):
    source: AlertSource
    alert: dict[str, Any]


class TriageRequest(BaseModel):
    source: AlertSource | None = None
    alert: dict[str, Any]
    normalized: bool = False


class TriageResponse(BaseModel):
    triage_id: str
    alert_id: str
    agent_run_id: str
    classification: Classification
    severity: Severity
    confidence: float
    model_confidence: float
    summary: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    requires_human_review: bool
    action_executed: str
    policy_adjustments: list[str] = Field(default_factory=list)
    tool_call_count: int


class AlertResponse(BaseModel):
    alert: NormalizedAlert


class HealthResponse(BaseModel):
    status: str
    version: str
    llm_provider: str
    tools: list[str]
    database: str
