from __future__ import annotations

from collections import defaultdict
from threading import Lock
from typing import Protocol


class MetricsExporter(Protocol):
    def increment(self, name: str, value: float) -> None: ...

    def observe(self, name: str, value: float) -> None: ...


class MetricsRegistry:
    """Lightweight in-process metrics with Prometheus-compatible exposition."""

    def __init__(self) -> None:
        self._counters: dict[str, float] = defaultdict(float)
        self._histograms: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
        self._exporter: MetricsExporter | None = None

    def configure_exporter(self, exporter: MetricsExporter | None) -> None:
        self._exporter = exporter

    def increment(self, name: str, value: float = 1.0) -> None:
        with self._lock:
            self._counters[name] += value
        if self._exporter is not None:
            self._exporter.increment(name, value)

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            self._histograms[name].append(value)
        if self._exporter is not None:
            self._exporter.observe(name, value)

    def counter(self, name: str) -> float:
        with self._lock:
            return self._counters.get(name, 0.0)

    def histogram_stats(self, name: str) -> dict[str, float]:
        with self._lock:
            values = list(self._histograms.get(name, []))
        if not values:
            return {"count": 0, "sum": 0.0, "avg": 0.0, "max": 0.0}
        return {
            "count": len(values),
            "sum": sum(values),
            "avg": sum(values) / len(values),
            "max": max(values),
        }

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "counters": dict(self._counters),
                "histograms": {k: self.histogram_stats(k) for k in self._histograms},
            }

    def render_prometheus(self) -> str:
        lines: list[str] = []
        with self._lock:
            for name, value in sorted(self._counters.items()):
                lines.append(f"# TYPE {name} counter")
                lines.append(f"{name} {value}")
            for name, values in sorted(self._histograms.items()):
                if not values:
                    continue
                lines.append(f"# TYPE {name} summary")
                lines.append(f"{name}_count {len(values)}")
                lines.append(f"{name}_sum {sum(values)}")
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._histograms.clear()


METRICS = MetricsRegistry()
