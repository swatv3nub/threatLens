from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from uuid import uuid4

from threatlens.observability.logging import get_logger, log_event
from threatlens.observability.otel import get_tracer

logger = get_logger("threatlens.trace")


@dataclass
class Span:
    name: str
    started_at: float = field(default_factory=time.monotonic)
    attributes: dict[str, object] = field(default_factory=dict)
    duration_ms: float = 0.0

    def finish(self) -> None:
        self.duration_ms = (time.monotonic() - self.started_at) * 1000.0


@dataclass
class Trace:
    trace_id: str = field(default_factory=lambda: uuid4().hex)
    spans: list[Span] = field(default_factory=list)

    @asynccontextmanager
    async def span(self, name: str, **attributes: object) -> AsyncIterator[Span]:
        s = Span(name=name, attributes=attributes)
        self.spans.append(s)
        otel_tracer = get_tracer()
        try:
            if otel_tracer is None:
                yield s
            else:
                with otel_tracer.start_as_current_span(name, attributes=attributes):
                    yield s
        finally:
            s.finish()
            log_event(
                logger,
                "span_complete",
                span=name,
                duration_ms=round(s.duration_ms, 2),
                **attributes,
            )
