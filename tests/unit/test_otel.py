from __future__ import annotations

from threatlens.observability.metrics import MetricsRegistry


class _Exporter:
    def __init__(self) -> None:
        self.counters: list[tuple[str, float]] = []
        self.histograms: list[tuple[str, float]] = []

    def increment(self, name: str, value: float) -> None:
        self.counters.append((name, value))

    def observe(self, name: str, value: float) -> None:
        self.histograms.append((name, value))


def test_metrics_registry_mirrors_values_to_exporter() -> None:
    registry = MetricsRegistry()
    exporter = _Exporter()
    registry.configure_exporter(exporter)

    registry.increment("alerts_processed_total")
    registry.observe("triage_latency_seconds", 0.25)

    assert exporter.counters == [("alerts_processed_total", 1.0)]
    assert exporter.histograms == [("triage_latency_seconds", 0.25)]
