from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from threatlens.models.alerts import AlertSource, NormalizedAlert


class IngestionError(ValueError):
    pass


@runtime_checkable
class Ingestor(Protocol):
    source: AlertSource

    def parse(self, raw: dict[str, Any]) -> NormalizedAlert: ...


_REGISTRY: dict[AlertSource, Ingestor] = {}


def register_ingestor(ingestor: Ingestor) -> None:
    _REGISTRY[ingestor.source] = ingestor


def get_ingestor(source: AlertSource | str) -> Ingestor:
    if isinstance(source, str):
        source = AlertSource(source)
    if source not in _REGISTRY:
        raise IngestionError(f"no ingestor registered for source {source!r}")
    return _REGISTRY[source]


def parse_alert(source: AlertSource | str, raw: dict[str, Any]) -> NormalizedAlert:
    return get_ingestor(source).parse(raw)


def _first(*values: Any) -> Any:
    for v in values:
        if v not in (None, "", [], {}):
            return v
    return None
