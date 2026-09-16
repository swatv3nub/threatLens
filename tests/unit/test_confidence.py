from __future__ import annotations

from threatlens.models.enrichment import EnrichmentContext
from threatlens.models.evidence import Evidence, EvidenceType
from threatlens.reasoning.confidence import ConfidenceCalculator


def _evidence(source: str, confidence: float) -> Evidence:
    return Evidence(
        source=source,
        type=EvidenceType.reputation,
        finding="f",
        confidence=confidence,
    )


def test_more_sources_increase_confidence() -> None:
    calc = ConfidenceCalculator()
    one = calc.calculate(
        model_confidence=0.8,
        evidence=[_evidence("abuseipdb", 0.8)],
        enrichment=EnrichmentContext(),
    )
    three = calc.calculate(
        model_confidence=0.8,
        evidence=[
            _evidence("abuseipdb", 0.8),
            _evidence("asset_context", 0.8),
            _evidence("mitre_attack", 0.8),
        ],
        enrichment=EnrichmentContext(),
    )
    assert three.final_confidence > one.final_confidence


def test_contradiction_penalty_reduces_confidence() -> None:
    calc = ConfidenceCalculator()
    evidence = [_evidence("abuseipdb", 0.8), _evidence("asset_context", 0.8)]
    base = calc.calculate(
        model_confidence=0.8, evidence=evidence, enrichment=EnrichmentContext()
    )
    penalized = calc.calculate(
        model_confidence=0.8,
        evidence=evidence,
        enrichment=EnrichmentContext(),
        has_contradiction=True,
    )
    assert penalized.final_confidence < base.final_confidence


def test_missing_context_reduces_confidence() -> None:
    calc = ConfidenceCalculator()
    evidence = [_evidence("abuseipdb", 0.8)]
    base = calc.calculate(
        model_confidence=0.8, evidence=evidence, enrichment=EnrichmentContext()
    )
    degraded = calc.calculate(
        model_confidence=0.8,
        evidence=evidence,
        enrichment=EnrichmentContext(degraded=True, missing_context=["asset missing"]),
    )
    assert degraded.final_confidence < base.final_confidence


def test_no_evidence_floors_confidence() -> None:
    calc = ConfidenceCalculator()
    result = calc.calculate(
        model_confidence=0.9, evidence=[], enrichment=EnrichmentContext()
    )
    assert result.final_confidence < 0.9
    assert result.notes
