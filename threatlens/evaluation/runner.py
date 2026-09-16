from __future__ import annotations

import time
from dataclasses import dataclass, field

from threatlens.agents.triage_agent import TriageAgent
from threatlens.evaluation.dataset import EvaluationCase, load_cases
from threatlens.ingestion.synthetic import SyntheticIngestor
from threatlens.models.reasoning import Classification


@dataclass
class CaseResult:
    case_id: str
    expected_classification: Classification
    actual_classification: Classification
    expected_severity: str
    actual_severity: str
    confidence: float
    evidence_count: int
    tool_calls: int
    latency_ms: float
    errors: list[str] = field(default_factory=list)

    @property
    def classification_match(self) -> bool:
        return self.expected_classification == self.actual_classification

    @property
    def severity_match(self) -> bool:
        return self.expected_severity == self.actual_severity


@dataclass
class EvaluationReport:
    results: list[CaseResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def classification_accuracy(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.classification_match for r in self.results) / len(self.results)

    @property
    def severity_agreement(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.severity_match for r in self.results) / len(self.results)

    @property
    def evidence_grounded(self) -> float:
        if not self.results:
            return 0.0
        grounded = sum(1 for r in self.results if r.evidence_count > 0)
        return grounded / len(self.results)

    @property
    def average_tool_calls(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.tool_calls for r in self.results) / len(self.results)

    @property
    def average_latency_ms(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.latency_ms for r in self.results) / len(self.results)

    @property
    def failure_rate(self) -> float:
        if not self.results:
            return 0.0
        failed = sum(1 for r in self.results if r.errors)
        return failed / len(self.results)

    def render(self) -> str:
        lines = [
            "Evaluation Results",
            "-" * 30,
            f"Alerts evaluated:        {self.total}",
            f"Classification accuracy: {self.classification_accuracy:.0%}",
            f"Severity agreement:      {self.severity_agreement:.0%}",
            f"Evidence grounded:       {self.evidence_grounded:.0%}",
            f"Average tool calls:      {self.average_tool_calls:.1f}",
            f"Average latency:         {self.average_latency_ms / 1000:.2f}s",
            f"Failure rate:            {self.failure_rate:.0%}",
        ]
        return "\n".join(lines)


class EvaluationRunner:
    def __init__(self, agent: TriageAgent) -> None:
        self._agent = agent

    async def run(self, cases: list[EvaluationCase] | None = None) -> EvaluationReport:
        cases = cases or load_cases()
        report = EvaluationReport()
        ingestor = SyntheticIngestor()
        for case in cases:
            start = time.monotonic()
            errors: list[str] = []
            try:
                alert = ingestor.parse(case.alert)
                triage = await self._agent.run(alert)
                latency = (time.monotonic() - start) * 1000.0
                report.results.append(
                    CaseResult(
                        case_id=case.id,
                        expected_classification=case.expected_classification,
                        actual_classification=triage.classification,
                        expected_severity=case.expected_severity.value,
                        actual_severity=triage.severity.value,
                        confidence=triage.confidence,
                        evidence_count=len(triage.evidence),
                        tool_calls=triage.tool_call_count,
                        latency_ms=latency,
                    )
                )
            except Exception as exc:
                latency = (time.monotonic() - start) * 1000.0
                errors.append(str(exc))
                report.results.append(
                    CaseResult(
                        case_id=case.id,
                        expected_classification=case.expected_classification,
                        actual_classification=Classification.needs_investigation,
                        expected_severity=case.expected_severity.value,
                        actual_severity="informational",
                        confidence=0.0,
                        evidence_count=0,
                        tool_calls=0,
                        latency_ms=latency,
                        errors=errors,
                    )
                )
        return report
