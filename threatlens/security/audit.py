from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "password",
    "secret",
    "token",
    "x-apikey",
    "openai_api_key",
    "virustotal_api_key",
    "abuseipdb_api_key",
}


def redact(payload: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if key.lower() in SENSITIVE_KEYS:
            cleaned[key] = "[REDACTED]"
        elif isinstance(value, dict):
            cleaned[key] = redact(value)
        elif isinstance(value, list):
            cleaned[key] = [redact(v) if isinstance(v, dict) else v for v in value]
        else:
            cleaned[key] = value
    return cleaned


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event_type: str
    alert_id: str | None = None
    triage_id: str | None = None
    agent_run_id: str | None = None
    request_id: str | None = None
    actor: str = "system"
    detail: dict[str, Any] = Field(default_factory=dict)

    def redacted_detail(self) -> dict[str, Any]:
        return redact(self.detail)


class AuditLog:
    """In-memory audit sink with optional durable persistence."""

    def __init__(self, persist: Callable[[AuditEvent], None] | None = None) -> None:
        self._events: list[AuditEvent] = []
        self._persist = persist

    def record(self, event: AuditEvent) -> AuditEvent:
        self._events.append(event)
        if self._persist is not None:
            self._persist(event)
        return event

    def emit(self, event_type: str, **kwargs: Any) -> AuditEvent:
        return self.record(AuditEvent(event_type=event_type, **kwargs))

    def all(self) -> list[AuditEvent]:
        return list(self._events)

    def for_alert(self, alert_id: str) -> list[AuditEvent]:
        return [e for e in self._events if e.alert_id == alert_id]

    def for_triage(self, triage_id: str) -> list[AuditEvent]:
        return [e for e in self._events if e.triage_id == triage_id]

    def clear(self) -> None:
        self._events.clear()
