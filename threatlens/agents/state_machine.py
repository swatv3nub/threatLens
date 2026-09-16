from __future__ import annotations

from enum import Enum

from threatlens.observability.logging import get_logger, log_event

logger = get_logger("threatlens.state")


class AgentState(str, Enum):
    RECEIVED = "RECEIVED"
    NORMALIZED = "NORMALIZED"
    CLASSIFIED = "CLASSIFIED"
    ENRICHING = "ENRICHING"
    EVIDENCE_VALIDATION = "EVIDENCE_VALIDATION"
    REASONING = "REASONING"
    DECISION_VALIDATION = "DECISION_VALIDATION"
    TRIAGE_GENERATION = "TRIAGE_GENERATION"
    COMPLETED = "COMPLETED"

    ENRICHMENT_FAILED = "ENRICHMENT_FAILED"
    REASONING_FAILED = "REASONING_FAILED"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    ESCALATED = "ESCALATED"


TERMINAL_STATES = {
    AgentState.COMPLETED,
    AgentState.ENRICHMENT_FAILED,
    AgentState.REASONING_FAILED,
    AgentState.VALIDATION_FAILED,
    AgentState.ESCALATED,
}

ALLOWED_TRANSITIONS: dict[AgentState, set[AgentState]] = {
    AgentState.RECEIVED: {AgentState.NORMALIZED, AgentState.VALIDATION_FAILED},
    AgentState.NORMALIZED: {AgentState.CLASSIFIED},
    AgentState.CLASSIFIED: {AgentState.ENRICHING},
    AgentState.ENRICHING: {
        AgentState.EVIDENCE_VALIDATION,
        AgentState.ENRICHMENT_FAILED,
    },
    AgentState.EVIDENCE_VALIDATION: {
        AgentState.REASONING,
        AgentState.REASONING_FAILED,
        AgentState.VALIDATION_FAILED,
    },
    AgentState.REASONING: {
        AgentState.DECISION_VALIDATION,
        AgentState.REASONING_FAILED,
    },
    AgentState.DECISION_VALIDATION: {
        AgentState.TRIAGE_GENERATION,
        AgentState.VALIDATION_FAILED,
    },
    AgentState.TRIAGE_GENERATION: {AgentState.COMPLETED, AgentState.ESCALATED},
    AgentState.COMPLETED: set(),
    AgentState.ENRICHMENT_FAILED: {AgentState.TRIAGE_GENERATION},
    AgentState.REASONING_FAILED: {AgentState.TRIAGE_GENERATION},
    AgentState.VALIDATION_FAILED: {AgentState.TRIAGE_GENERATION},
    AgentState.ESCALATED: set(),
}


class InvalidStateTransition(RuntimeError):
    pass


class StateMachine:
    def __init__(self, *, alert_id: str, agent_run_id: str) -> None:
        self._state = AgentState.RECEIVED
        self.alert_id = alert_id
        self.agent_run_id = agent_run_id
        self.history: list[tuple[AgentState, AgentState]] = []

    @property
    def state(self) -> AgentState:
        return self._state

    @property
    def is_terminal(self) -> bool:
        return self._state in TERMINAL_STATES

    def can_transition(self, target: AgentState) -> bool:
        return target in ALLOWED_TRANSITIONS[self._state]

    def transition(self, target: AgentState) -> AgentState:
        if not self.can_transition(target):
            raise InvalidStateTransition(
                f"illegal transition {self._state.value} -> {target.value}"
            )
        previous = self._state
        self._state = target
        self.history.append((previous, target))
        log_event(
            logger,
            "agent_state_transition",
            alert_id=self.alert_id,
            agent_run_id=self.agent_run_id,
            from_state=previous.value,
            to_state=target.value,
        )
        return target

    def force(self, target: AgentState) -> AgentState:
        previous = self._state
        self._state = target
        self.history.append((previous, target))
        log_event(
            logger,
            "agent_state_forced",
            alert_id=self.alert_id,
            agent_run_id=self.agent_run_id,
            from_state=previous.value,
            to_state=target.value,
        )
        return target
