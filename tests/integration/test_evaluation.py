from __future__ import annotations

import pytest

from threatlens.agents.triage_agent import TriageAgent
from threatlens.container import Container
from threatlens.evaluation.runner import EvaluationRunner


@pytest.fixture()
def agent(settings) -> TriageAgent:
    container = Container(settings)
    return container.agent


async def test_evaluation_runner_produces_report(agent: TriageAgent) -> None:
    runner = EvaluationRunner(agent)
    report = await runner.run()
    assert report.total == 10
    assert 0.0 <= report.classification_accuracy <= 1.0
    assert 0.0 <= report.severity_agreement <= 1.0
    assert 0.0 <= report.evidence_grounded <= 1.0
    assert report.average_tool_calls >= 0
    assert "Evaluation Results" in report.render()
