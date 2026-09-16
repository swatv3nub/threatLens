from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from threatlens.models.alerts import Severity
from threatlens.models.evidence import Evidence
from threatlens.models.reasoning import Classification, RecommendedAction


class TriageResult(BaseModel):
    triage_id: str
    alert_id: str
    agent_run_id: str
    classification: Classification
    severity: Severity
    model_confidence: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    evidence: list[Evidence] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    requires_human_review: bool = True
    action_executed: str = "none"
    policy_adjustments: list[str] = Field(default_factory=list)
    tool_call_count: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def to_analyst_note(self) -> str:
        lines: list[str] = []
        lines.append("SECURITY ALERT TRIAGE")
        lines.append("-" * 60)
        lines.append(f"Classification: {self.classification.value.upper()}")
        lines.append(f"Severity:       {self.severity.value.upper()}")
        lines.append(f"Confidence:     {self.confidence:.0%}")
        lines.append("")
        lines.append("Summary:")
        lines.append(f"  {self.summary}")
        lines.append("")
        if self.evidence:
            lines.append("Key Evidence:")
            for ev in self.evidence:
                lines.append(f"  - [{ev.id}] {ev.finding} ({ev.source})")
            lines.append("")
        if self.recommended_actions:
            lines.append("Recommended Actions (NOT executed automatically):")
            for i, act in enumerate(self.recommended_actions, 1):
                lines.append(f"  {i}. {act.action}")
                lines.append(f"     Rationale: {act.rationale}")
            lines.append("")
        if self.mitre_attack:
            lines.append("MITRE ATT&CK: " + ", ".join(self.mitre_attack))
            lines.append("")
        if self.uncertainties:
            lines.append("Uncertainty:")
            for u in self.uncertainties:
                lines.append(f"  - {u}")
            lines.append("")
        lines.append(f"Action Executed: {self.action_executed.upper()}")
        lines.append(f"Human Review Required: {'YES' if self.requires_human_review else 'NO'}")
        if self.policy_adjustments:
            lines.append("")
            lines.append("Policy Adjustments:")
            for adj in self.policy_adjustments:
                lines.append(f"  - {adj}")
        return "\n".join(lines)
