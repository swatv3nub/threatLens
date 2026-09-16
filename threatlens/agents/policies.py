from __future__ import annotations

from pydantic import BaseModel, Field

from threatlens.models.alerts import NormalizedAlert, Severity, max_severity
from threatlens.models.enrichment import EnrichmentContext
from threatlens.models.reasoning import Classification, ReasoningResult

MINIMUM_SEVERITY = {
    "known_malicious_ip_critical_asset": Severity.high,
    "confirmed_malware_hash": Severity.high,
    "critical_asset_suspicious": Severity.critical,
}

CRITICAL_ENVIRONMENTS = {"production"}
CRITICAL_LEVELS = {"critical"}


class PolicyDecision(BaseModel):
    severity: Severity
    classification: Classification
    requires_human_review: bool = True
    escalation_required: bool = False
    adjustments: list[str] = Field(default_factory=list)


class PolicyEngine:
    """Deterministic guardrails that the LLM cannot override."""

    def apply(
        self,
        *,
        alert: NormalizedAlert,
        enrichment: EnrichmentContext,
        reasoning: ReasoningResult,
    ) -> PolicyDecision:
        severity = reasoning.severity
        classification = reasoning.classification
        requires_review = reasoning.classification in {
            Classification.needs_investigation,
            Classification.true_positive,
        }
        escalation = reasoning.escalation_required
        adjustments: list[str] = []

        malicious_ip = any(r.malicious for r in enrichment.ip_reputations)
        malicious_domain = any(r.malicious for r in enrichment.domain_reputations)
        malicious_url = any(r.malicious for r in enrichment.url_reputations)
        malicious_file = any(r.malicious for r in enrichment.file_reputations)
        any_malicious = malicious_ip or malicious_domain or malicious_url or malicious_file

        critical_asset = any(
            a.criticality.lower() in CRITICAL_LEVELS
            or a.environment.lower() in CRITICAL_ENVIRONMENTS
            for a in enrichment.assets
        )

        if malicious_file:
            severity = max_severity(severity, Severity.high)
            adjustments.append("confirmed malware hash -> minimum severity HIGH")
        if any_malicious and critical_asset:
            severity = max_severity(severity, Severity.high)
            adjustments.append("malicious indicator + critical asset -> minimum severity HIGH")
        if critical_asset and alert.severity in {Severity.high, Severity.critical}:
            severity = max_severity(severity, Severity.critical)
            adjustments.append("critical asset + high alert severity -> escalate")

        if any_malicious and classification in {
            Classification.false_positive,
            Classification.benign,
        }:
            classification = Classification.needs_investigation
            adjustments.append(
                "policy overrode benign classification: malicious indicator present"
            )
            requires_review = True

        if reasoning.classification == Classification.true_positive:
            escalation = escalation or critical_asset

        if enrichment.degraded and reasoning.classification == Classification.true_positive:
            requires_review = True
            adjustments.append("degraded enrichment -> human review required")

        if enrichment.missing_context:
            requires_review = True

        return PolicyDecision(
            severity=severity,
            classification=classification,
            requires_human_review=requires_review,
            escalation_required=escalation,
            adjustments=adjustments,
        )
