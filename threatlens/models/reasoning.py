from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from threatlens.models.alerts import Severity


class Classification(str, Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    benign = "benign"
    needs_investigation = "needs_investigation"


class RecommendedAction(BaseModel):
    action: str
    rationale: str
    priority: int = Field(default=3, ge=1, le=5)
    requires_human_approval: bool = True


class EvidenceReference(BaseModel):
    evidence_id: str
    source: str
    finding: str


class ReasoningResult(BaseModel):
    classification: Classification
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    model_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    inferences: list[str] = Field(default_factory=list)
    decision: str = ""
    reasoning_summary: str = ""
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    escalation_required: bool = False
    uncertainties: list[str] = Field(default_factory=list)


class RawReasoningOutput(BaseModel):
    """Schema the LLM must produce. Evidence references are IDs only."""

    classification: Classification
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    inferences: list[str] = Field(default_factory=list)
    reasoning_summary: str = ""
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    escalation_required: bool = False
    uncertainties: list[str] = Field(default_factory=list)
