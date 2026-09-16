from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from threatlens import __version__
from threatlens.api.dependencies import get_container_dep, require_role
from threatlens.api.schemas import HealthResponse
from threatlens.container import Container
from threatlens.observability.metrics import METRICS

router = APIRouter(prefix="/v1", tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health(container: Container = Depends(get_container_dep)) -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=__version__,
        llm_provider=container.llm.name,
        tools=container.registry.names(),
        database="configured",
    )


@router.get("/metrics")
async def metrics(_: None = Depends(require_role("admin"))) -> dict[str, object]:
    return METRICS.snapshot()


@router.get("/metrics/prometheus", response_class=PlainTextResponse)
async def metrics_prometheus(_: None = Depends(require_role("admin"))) -> str:
    return METRICS.render_prometheus()
