from __future__ import annotations

import time
from dataclasses import dataclass, field
from uuid import uuid4

from threatlens.agents.policies import PolicyDecision, PolicyEngine
from threatlens.agents.state_machine import AgentState, StateMachine
from threatlens.enrichment.base import ToolResult
from threatlens.enrichment.engine import EnrichmentEngine
from threatlens.models.alerts import NormalizedAlert
from threatlens.models.enrichment import EnrichmentContext
from threatlens.models.evidence import Evidence
from threatlens.models.reasoning import ReasoningResult
from threatlens.models.triage import TriageResult
from threatlens.observability.logging import (
    agent_run_id_var,
    alert_id_var,
    get_logger,
    log_event,
    triage_id_var,
)
from threatlens.observability.metrics import METRICS
from threatlens.observability.tracing import Trace
from threatlens.reasoning.engine import ReasoningEngine, deterministic_fallback
from threatlens.reasoning.schemas import EvidenceBundle
from threatlens.security.audit import AuditLog
from threatlens.security.prompt_guard import scan_alert_fields
from threatlens.security.rate_limiter import ToolBudget

logger = get_logger("threatlens.agent")


@dataclass
class TriageState:
    alert: NormalizedAlert
    agent_run_id: str = field(default_factory=lambda: str(uuid4()))
    triage_id: str = field(default_factory=lambda: str(uuid4()))
    enrichment: EnrichmentContext = field(default_factory=EnrichmentContext)
    tool_results: list[ToolResult] = field(default_factory=list)
    evidence_bundle: EvidenceBundle = field(default_factory=EvidenceBundle)
    reasoning: ReasoningResult | None = None
    policy_adjustments: list[str] = field(default_factory=list)
    final_triage: TriageResult | None = None
    requires_human_review: bool = True
    injection_flagged: bool = False
    errors: list[str] = field(default_factory=list)

    def evidence_ids(self) -> list[str]:
        return self.evidence_bundle.ids()


class TriageAgent:
    def __init__(
        self,
        *,
        enrichment: EnrichmentEngine,
        reasoning: ReasoningEngine,
        policies: PolicyEngine | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self._enrichment = enrichment
        self._reasoning = reasoning
        self._policies = policies or PolicyEngine()
        self._audit = audit or AuditLog()

    async def run(self, alert: NormalizedAlert) -> TriageResult:
        state = TriageState(alert=alert)
        machine = StateMachine(alert_id=alert.id, agent_run_id=state.agent_run_id)
        agent_run_id_var.set(state.agent_run_id)
        alert_id_var.set(alert.id)
        triage_id_var.set(state.triage_id)
        trace = Trace()
        METRICS.increment("alerts_processed_total")
        start = time.monotonic()

        self._audit.emit(
            "investigation_started",
            alert_id=alert.id,
            triage_id=state.triage_id,
            agent_run_id=state.agent_run_id,
            detail={"source": alert.source.value},
        )

        run_budget = ToolBudget(self._tool_budget())
        self._enrichment.set_budget(run_budget)

        machine.transition(AgentState.NORMALIZED)
        machine.transition(AgentState.CLASSIFIED)

        injection = scan_alert_fields(alert)
        if injection.suspicious:
            state.injection_flagged = True
            state.errors.append("prompt_injection_suspected")
            METRICS.increment("prompt_injection_detected_total")
            log_event(
                logger,
                "prompt_injection_suspected",
                alert_id=alert.id,
                fields=[f.field for f in injection.findings],
            )
            self._audit.emit(
                "prompt_injection_detected",
                alert_id=alert.id,
                agent_run_id=state.agent_run_id,
                detail={"fields": sorted({f.field for f in injection.findings})},
            )

        async with trace.span("enrichment", alert_id=alert.id):
            machine.transition(AgentState.ENRICHING)
            try:
                enrichment, tool_results = await self._enrichment.run(
                    alert, agent_run_id=state.agent_run_id
                )
                state.enrichment = enrichment
                state.tool_results = tool_results
            except Exception as exc:
                state.errors.append(f"enrichment: {exc}")
                enrichment = EnrichmentContext(degraded=True)
                enrichment.tool_errors.append(str(exc))
                state.enrichment = enrichment
                machine.transition(AgentState.ENRICHMENT_FAILED)
                METRICS.increment("agent_failures_total")

        if machine.state == AgentState.ENRICHING:
            machine.transition(AgentState.EVIDENCE_VALIDATION)

        state.evidence_bundle = self._reasoning.build_evidence(alert, state.enrichment)
        self._audit.emit(
            "evidence_built",
            alert_id=alert.id,
            triage_id=state.triage_id,
            agent_run_id=state.agent_run_id,
            detail={
                "evidence_ids": state.evidence_bundle.ids(),
                "evidence_count": len(state.evidence_bundle.evidence),
            },
        )

        async with trace.span("reasoning", alert_id=alert.id):
            try:
                reasoning = await self._reasoning.reason(
                    alert, state.enrichment, bundle=state.evidence_bundle
                )
                state.reasoning = reasoning
                self._audit.emit(
                    "reasoning_completed",
                    alert_id=alert.id,
                    triage_id=state.triage_id,
                    agent_run_id=state.agent_run_id,
                    detail={
                        "model_confidence": reasoning.model_confidence,
                        "confidence": reasoning.confidence,
                        "evidence_ids": [e.evidence_id for e in reasoning.evidence],
                    },
                )
            except Exception as exc:
                state.errors.append(f"reasoning: {exc}")
                state.reasoning = deterministic_fallback(alert)
                METRICS.increment("agent_failures_total")
                if machine.state != AgentState.ENRICHMENT_FAILED:
                    machine.transition(AgentState.REASONING_FAILED)

        if machine.state == AgentState.EVIDENCE_VALIDATION:
            machine.transition(AgentState.REASONING)
            machine.transition(AgentState.DECISION_VALIDATION)

        reasoning = state.reasoning
        if reasoning is None:
            raise RuntimeError("reasoning result missing after agent execution")
        decision = self._policies.apply(
            alert=alert, enrichment=state.enrichment, reasoning=reasoning
        )
        state.policy_adjustments = decision.adjustments
        self._audit.emit(
            "policy_decision",
            alert_id=alert.id,
            triage_id=state.triage_id,
            agent_run_id=state.agent_run_id,
            detail={
                "classification": decision.classification.value,
                "severity": decision.severity.value,
                "requires_human_review": decision.requires_human_review,
                "adjustments": decision.adjustments,
            },
        )

        if decision.requires_human_review:
            state.requires_human_review = True

        final = self._build_triage(state, decision)
        state.final_triage = final

        if machine.state != AgentState.DECISION_VALIDATION:
            machine.force(AgentState.TRIAGE_GENERATION)
        else:
            machine.transition(AgentState.TRIAGE_GENERATION)

        if final.classification.value == "true_positive" and decision.escalation_required:
            machine.force(AgentState.ESCALATED)
        else:
            machine.transition(AgentState.COMPLETED)

        METRICS.observe("triage_latency_seconds", time.monotonic() - start)
        self._audit.emit(
            "triage_completed",
            alert_id=alert.id,
            triage_id=final.triage_id,
            agent_run_id=state.agent_run_id,
            detail={
                "classification": final.classification.value,
                "severity": final.severity.value,
                "confidence": round(final.confidence, 3),
                "final_state": machine.state.value,
                "tool_calls": final.tool_call_count,
                "policy_adjustments": decision.adjustments,
            },
        )
        METRICS.increment("triage_completed_total")
        METRICS.increment(f"classification_{final.classification.value}_total")
        METRICS.increment(f"severity_{final.severity.value}_total")
        METRICS.observe("triage_tool_calls", float(final.tool_call_count))
        log_event(
            logger,
            "agent_run_complete",
            alert_id=alert.id,
            final_state=machine.state.value,
            classification=final.classification.value,
            severity=final.severity.value,
        )
        return final

    def _build_triage(self, state: TriageState, decision: PolicyDecision) -> TriageResult:
        reasoning = state.reasoning
        if reasoning is None:
            raise RuntimeError("reasoning result missing while building triage")
        evidence_by_id = {e.id: e for e in state.evidence_bundle.evidence}
        referenced = [e for e in reasoning.evidence if e.evidence_id in evidence_by_id]
        ordered_evidence: list[Evidence] = [
            evidence_by_id[ref.evidence_id] for ref in referenced
        ]
        if not ordered_evidence:
            ordered_evidence = list(state.evidence_bundle.evidence)
        mitre = [
            f"{tech.technique_id} {tech.technique_name}"
            for tech in state.enrichment.mitre_techniques
        ]
        tool_calls = sum(1 for r in state.tool_results if r.ok)
        uncertainties = list(reasoning.uncertainties)
        if state.injection_flagged:
            uncertainties.append(
                "Alert content contained text resembling prompt injection and was "
                "treated strictly as untrusted data."
            )
        requires_review = decision.requires_human_review or state.injection_flagged
        return TriageResult(
            triage_id=state.triage_id,
            alert_id=state.alert.id,
            agent_run_id=state.agent_run_id,
            classification=decision.classification,
            severity=decision.severity,
            model_confidence=reasoning.model_confidence,
            confidence=reasoning.confidence,
            summary=reasoning.reasoning_summary,
            evidence=ordered_evidence,
            recommended_actions=reasoning.recommended_actions,
            mitre_attack=mitre,
            uncertainties=uncertainties,
            requires_human_review=requires_review,
            action_executed="none",
            policy_adjustments=decision.adjustments,
            tool_call_count=tool_calls,
        )

    def _tool_budget(self) -> int:
        return self._enrichment.max_tool_calls
