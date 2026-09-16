from __future__ import annotations

from collections.abc import Mapping
from threading import Lock
from typing import Any

from threatlens.config import Settings
from threatlens.observability.logging import get_logger

logger = get_logger("threatlens.otel")

_lock = Lock()
_configured = False
_tracer: Any = None
_metrics_bridge: Any = None


def configure_telemetry(settings: Settings) -> bool:
    """Configure optional OTLP tracing and metrics without making it mandatory."""
    global _configured, _tracer, _metrics_bridge
    if not settings.otel_enabled:
        return False
    with _lock:
        if _configured:
            return _tracer is not None
        _configured = True
        try:
            from opentelemetry import metrics, trace
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
                OTLPMetricExporter,
            )
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            resource = Resource.create({"service.name": settings.otel_service_name})
            endpoint = settings.otel_exporter_otlp_endpoint
            headers = _parse_headers(settings.otel_exporter_otlp_headers)
            trace_exporter = OTLPSpanExporter(endpoint=_endpoint(endpoint, "traces"), headers=headers)
            metric_exporter = OTLPMetricExporter(
                endpoint=_endpoint(endpoint, "metrics"), headers=headers
            )

            tracer_provider = TracerProvider(resource=resource)
            tracer_provider.add_span_processor(BatchSpanProcessor(trace_exporter))
            trace.set_tracer_provider(tracer_provider)
            _tracer = trace.get_tracer(settings.otel_service_name)

            reader = PeriodicExportingMetricReader(metric_exporter)
            metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[reader]))
            _metrics_bridge = _MetricsBridge(settings.otel_service_name)
            logger.info("OpenTelemetry OTLP export enabled")
            return True
        except ImportError:
            logger.warning(
                "OTEL_ENABLED is true but OpenTelemetry extras are not installed; "
                "install threatlens[otel]"
            )
        except Exception as exc:
            logger.warning("OpenTelemetry setup failed; continuing without export: %s", exc)
        return False


def get_tracer() -> Any:
    return _tracer


def get_metrics_bridge() -> Any:
    return _metrics_bridge


class _MetricsBridge:
    def __init__(self, service_name: str) -> None:
        from opentelemetry import metrics

        self._meter = metrics.get_meter(service_name)
        self._counters: dict[str, Any] = {}
        self._histograms: dict[str, Any] = {}

    def increment(self, name: str, value: float) -> None:
        counter = self._counters.setdefault(name, self._meter.create_counter(name))
        counter.add(value)

    def observe(self, name: str, value: float) -> None:
        histogram = self._histograms.setdefault(name, self._meter.create_histogram(name))
        histogram.record(value)


def _endpoint(endpoint: str | None, signal: str) -> str | None:
    if endpoint is None:
        return None
    return endpoint.rstrip("/") + "/" + signal


def _parse_headers(value: str | None) -> Mapping[str, str] | None:
    if not value:
        return None
    headers: dict[str, str] = {}
    for item in value.split(","):
        key, separator, header_value = item.partition("=")
        if separator and key.strip():
            headers[key.strip()] = header_value.strip()
    return headers or None
