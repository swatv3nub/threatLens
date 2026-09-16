from __future__ import annotations

import pytest

from threatlens.agents.state_machine import (
    AgentState,
    InvalidStateTransition,
    StateMachine,
)


def test_happy_path_transitions() -> None:
    sm = StateMachine(alert_id="a", agent_run_id="r")
    assert sm.state == AgentState.RECEIVED
    sm.transition(AgentState.NORMALIZED)
    sm.transition(AgentState.CLASSIFIED)
    sm.transition(AgentState.ENRICHING)
    sm.transition(AgentState.EVIDENCE_VALIDATION)
    sm.transition(AgentState.REASONING)
    sm.transition(AgentState.DECISION_VALIDATION)
    sm.transition(AgentState.TRIAGE_GENERATION)
    sm.transition(AgentState.COMPLETED)
    assert sm.is_terminal


def test_illegal_transition_rejected() -> None:
    sm = StateMachine(alert_id="a", agent_run_id="r")
    with pytest.raises(InvalidStateTransition):
        sm.transition(AgentState.REASONING)


def test_failure_states_can_recover() -> None:
    sm = StateMachine(alert_id="a", agent_run_id="r")
    sm.transition(AgentState.NORMALIZED)
    sm.transition(AgentState.CLASSIFIED)
    sm.transition(AgentState.ENRICHING)
    sm.transition(AgentState.ENRICHMENT_FAILED)
    sm.transition(AgentState.TRIAGE_GENERATION)
    assert not sm.is_terminal


def test_history_recorded() -> None:
    sm = StateMachine(alert_id="a", agent_run_id="r")
    sm.transition(AgentState.NORMALIZED)
    assert sm.history == [(AgentState.RECEIVED, AgentState.NORMALIZED)]
