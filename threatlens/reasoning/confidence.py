from __future__ import annotations

from pydantic import BaseModel, Field

from threatlens.models.enrichment import EnrichmentContext
from threatlens.models.evidence import Evidence


class ConfidenceBreakdown(BaseModel):
    model_confidence: float = Field(ge=0.0, le=1.0)
    evidence_confidence: float = Field(ge=0.0, le=1.0)
    tool_reliability: float = Field(ge=0.0, le=1.0)
    contradiction_penalty: float = Field(ge=0.0, le=1.0)
    missing_telemetry_penalty: float = Field(ge=0.0, le=1.0)
    final_confidence: float = Field(ge=0.0, le=1.0)
    notes: list[str] = Field(default_factory=list)


class ConfidenceCalculator:
    """Heuristic confidence combiner.

    This is NOT a calibrated probability. It blends model self-assessment,
    evidence coverage, tool reliability, and explicit penalties so that the
    final number reflects more than the LLM's own opinion.
    """

    def __init__(self, tool_reliability: dict[str, float] | None = None) -> None:
        self._reliability = tool_reliability or {
            "virustotal": 0.9,
            "abuseipdb": 0.85,
            "asset_context": 0.95,
            "alert_history": 0.8,
            "mitre_attack": 0.75,
        }

    def calculate(
        self,
        *,
        model_confidence: float,
        evidence: list[Evidence],
        enrichment: EnrichmentContext,
        has_contradiction: bool = False,
    ) -> ConfidenceBreakdown:
        notes: list[str] = []
        if evidence:
            evidence_conf = sum(e.confidence for e in evidence) / len(evidence)
        else:
            evidence_conf = 0.2
            notes.append("No evidence objects were produced; confidence floored.")
        sources = {e.source for e in evidence}
        diversity_bonus = min(0.15, 0.05 * max(0, len(sources) - 1))
        evidence_conf = min(1.0, evidence_conf + diversity_bonus)
        if len(sources) >= 3:
            notes.append(f"{len(sources)} independent evidence sources agree.")

        reliabilities = [self._reliability.get(src, 0.6) for src in sources]
        tool_rel = sum(reliabilities) / len(reliabilities) if reliabilities else 0.5

        contradiction_penalty = 0.15 if has_contradiction else 0.0
        if has_contradiction:
            notes.append("Conflicting enrichment results detected; confidence reduced.")

        missing_penalty = 0.0
        if enrichment.missing_context:
            missing_penalty += min(0.2, 0.05 * len(enrichment.missing_context))
            notes.append("Missing context reduced confidence.")
        if enrichment.degraded:
            missing_penalty += 0.15
            notes.append("Enrichment degraded (tool failure); confidence reduced.")

        blended = 0.45 * model_confidence + 0.35 * evidence_conf + 0.20 * tool_rel
        final = blended - contradiction_penalty - missing_penalty
        final = max(0.05, min(0.99, final))
        return ConfidenceBreakdown(
            model_confidence=model_confidence,
            evidence_confidence=evidence_conf,
            tool_reliability=tool_rel,
            contradiction_penalty=contradiction_penalty,
            missing_telemetry_penalty=missing_penalty,
            final_confidence=final,
            notes=notes,
        )
