from __future__ import annotations

from threatlens.agents.policies import PolicyEngine
from threatlens.models.alerts import NormalizedAlert, Severity
from threatlens.models.enrichment import (
    AssetContext,
    EnrichmentContext,
    FileReputation,
    IPReputation,
)
from threatlens.models.reasoning import Classification, ReasoningResult


def _reasoning(**kwargs) -> ReasoningResult:
    defaults = {
        "classification": Classification.false_positive,
        "severity": Severity.low,
        "confidence": 0.5,
        "reasoning_summary": "test",
    }
    defaults.update(kwargs)
    return ReasoningResult(**defaults)


def test_malicious_hash_forces_high_severity() -> None:
    alert = NormalizedAlert(source="synthetic")
    enrichment = EnrichmentContext(
        file_reputations=[
            FileReputation(file_hash="a" * 32, malicious=True, detections=50)
        ]
    )
    decision = PolicyEngine().apply(
        alert=alert,
        enrichment=enrichment,
        reasoning=_reasoning(severity=Severity.low),
    )
    assert decision.severity in {Severity.high, Severity.critical}


def test_malicious_ip_on_critical_asset_overrides_benign() -> None:
    alert = NormalizedAlert(source="synthetic", severity=Severity.high)
    enrichment = EnrichmentContext(
        ip_reputations=[
            IPReputation(ip="203.0.113.66", malicious=True, confidence_score=100)
        ],
        assets=[
            AssetContext(
                hostname="payments-prod-01",
                criticality="critical",
                environment="production",
            )
        ],
    )
    decision = PolicyEngine().apply(
        alert=alert,
        enrichment=enrichment,
        reasoning=_reasoning(classification=Classification.benign, severity=Severity.low),
    )
    assert decision.classification == Classification.needs_investigation
    assert decision.severity in {Severity.high, Severity.critical}
    assert decision.adjustments


def test_degraded_enrichment_requires_human_review() -> None:
    alert = NormalizedAlert(source="synthetic")
    enrichment = EnrichmentContext(degraded=True)
    decision = PolicyEngine().apply(
        alert=alert,
        enrichment=enrichment,
        reasoning=_reasoning(classification=Classification.true_positive),
    )
    assert decision.requires_human_review is True
