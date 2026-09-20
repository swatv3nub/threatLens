from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from threatlens.api.dependencies import (
    enforce_rate_limit,
    get_container_dep,
    require_role,
)
from threatlens.container import Container
from threatlens.ingestion.base import IngestionError
from threatlens.ingestion.reconix_cloud import ReconixCloudIngestor

router = APIRouter(
    prefix="/v1/ingest",
    tags=["ingestion"],
)


@router.post(
    "/reconix-cloud/{scan_id}",
    status_code=status.HTTP_200_OK,
)
async def ingest_reconix_cloud(
    scan_id: str,
    container: Container = Depends(get_container_dep),
    _: None = Depends(enforce_rate_limit),
    __: None = Depends(require_role("analyst")),
) -> dict[str, object]:
    try:
        alerts = ReconixCloudIngestor().ingest(scan_id)
    except IngestionError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    for alert in alerts:
        container.uow.alerts.save(alert)
        container.audit.emit(
            "alert_ingested",
            alert_id=alert.id,
            source="reconix_cloud",
            scan_id=scan_id,
        )

    return {
        "scan_id": scan_id,
        "ingested": len(alerts),
        "alert_ids": [alert.id for alert in alerts],
    }
