from __future__ import annotations

from threatlens.llm.base import (
    LLMError,
    LLMProvider,
    StructuredGenerationError,
)
from threatlens.models.alerts import NormalizedAlert
from threatlens.models.enrichment import EnrichmentContext
from threatlens.models.evidence import Evidence
from threatlens.models.reasoning import (
    EvidenceReference,
    RawReasoningOutput,
    ReasoningResult,
)
from threatlens.observability.logging import get_logger, log_event
from threatlens.reasoning.confidence import ConfidenceCalculator
from threatlens.reasoning.evidence_builder import EvidenceBuilder
from threatlens.reasoning.prompts import build_prompt
from threatlens.reasoning.schemas import EvidenceBundle

logger = get_logger("threatlens.reasoning")


class ReasoningError(RuntimeError):
    pass


class ReasoningEngine:
    def __init__(
        self,
        provider: LLMProvider,
        confidence: ConfidenceCalculator | None = None,
        evidence_builder: EvidenceBuilder | None = None,
    ) -> None:
        self._provider = provider
        self._confidence = confidence or ConfidenceCalculator()
        self._evidence_builder = evidence_builder or EvidenceBuilder()

    def build_evidence(
        self, alert: NormalizedAlert, enrichment: EnrichmentContext
    ) -> EvidenceBundle:
        return self._evidence_builder.build(alert, enrichment)

    async def reason(
        self,
        alert: NormalizedAlert,
        enrichment: EnrichmentContext,
        bundle: EvidenceBundle | None = None,
    ) -> ReasoningResult:
        bundle = bundle or self._evidence_builder.build(alert, enrichment)
        prompt = build_prompt(alert)
        input_data = {
            "alert": self._untrusted_view(alert),
            "evidence": [e.model_dump(mode="json") for e in bundle.evidence],
            "observations": bundle.observations,
            "signals": bundle.signals,
        }
        try:
            raw = await self._provider.generate_structured(
                system_prompt=prompt,
                input_data=input_data,
                response_model=RawReasoningOutput,
            )
        except StructuredGenerationError as exc:
            log_event(logger, "reasoning_schema_failure", alert_id=alert.id, error=str(exc))
            raise ReasoningError(f"LLM returned invalid structured output: {exc}") from exc
        except LLMError as exc:
            log_event(logger, "reasoning_llm_failure", alert_id=alert.id, error=str(exc))
            raise ReasoningError(f"LLM unavailable: {exc}") from exc

        return self._validate(raw, bundle.evidence, alert, enrichment)

    def _validate(
        self,
        raw: RawReasoningOutput,
        evidence: list[Evidence],
        alert: NormalizedAlert,
        enrichment: EnrichmentContext,
    ) -> ReasoningResult:
        by_id = {e.id: e for e in evidence}
        referenced: list[EvidenceReference] = []
        unknown: list[str] = []
        for evidence_id in raw.evidence_ids:
            ev = by_id.get(evidence_id)
            if ev is None:
                unknown.append(evidence_id)
                continue
            referenced.append(
                EvidenceReference(
                    evidence_id=ev.id, source=ev.source, finding=ev.finding
                )
            )
        if unknown:
            log_event(
                logger,
                "reasoning_unknown_evidence",
                alert_id=alert.id,
                unknown=unknown,
            )
        has_contradiction = self._detect_contradiction(enrichment)
        breakdown = self._confidence.calculate(
            model_confidence=raw.confidence,
            evidence=evidence,
            enrichment=enrichment,
            has_contradiction=has_contradiction,
        )
        return ReasoningResult(
            classification=raw.classification,
            severity=raw.severity,
            confidence=breakdown.final_confidence,
            model_confidence=raw.confidence,
            evidence=referenced,
            observations=raw.observations or [],
            inferences=raw.inferences or [],
            decision=raw.reasoning_summary,
            reasoning_summary=raw.reasoning_summary,
            recommended_actions=raw.recommended_actions,
            escalation_required=raw.escalation_required,
            uncertainties=raw.uncertainties,
        )

    @staticmethod
    def _detect_contradiction(enrichment: EnrichmentContext) -> bool:
        flags = [r.malicious for r in enrichment.ip_reputations]
        if flags and any(flags) and not all(flags):
            return True
        file_flags = [r.malicious for r in enrichment.file_reputations]
        return bool(file_flags and any(file_flags) and not all(file_flags))

    @staticmethod
    def _untrusted_view(alert: NormalizedAlert) -> dict[str, object]:
        data = alert.model_dump(mode="json")
        data.pop("raw_event", None)
        return data


def deterministic_fallback(alert: NormalizedAlert) -> ReasoningResult:
    from threatlens.models.alerts import Severity
    from threatlens.models.reasoning import Classification

    severity = alert.severity if alert.severity != Severity.informational else Severity.medium
    return ReasoningResult(
        classification=Classification.needs_investigation,
        severity=severity,
        confidence=0.3,
        model_confidence=0.3,
        evidence=[],
        observations=["Reasoning model unavailable; deterministic fallback applied."],
        inferences=[],
        decision="Fallback triage due to unavailable LLM.",
        reasoning_summary=(
            "The reasoning model was unavailable. This alert is routed for human "
            "review using the deterministic baseline severity only."
        ),
        recommended_actions=[],
        escalation_required=severity in {Severity.high, Severity.critical},
        uncertainties=["LLM reasoning unavailable; no semantic analysis performed."],
    )
