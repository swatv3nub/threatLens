from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from threatlens.api.dependencies import enforce_rate_limit, get_container_dep, require_role
from threatlens.api.schemas import AlertResponse, AlertSubmission
from threatlens.container import Container
from threatlens.ingestion.base import IngestionError, parse_alert

router = APIRouter(prefix="/v1/alerts", tags=["alerts"])


@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
async def create_alert(
    submission: AlertSubmission,
    container: Container = Depends(get_container_dep),
    _: None = Depends(enforce_rate_limit),
    __: None = Depends(require_role("analyst")),
) -> AlertResponse:
    try:
        alert = parse_alert(submission.source, submission.alert)
    except IngestionError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    container.uow.alerts.save(alert)
    container.audit.emit("alert_ingested", alert_id=alert.id)
    return AlertResponse(alert=alert)


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    container: Container = Depends(get_container_dep),
    _: None = Depends(require_role("viewer")),
) -> AlertResponse:
    alert = container.uow.alerts.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")
    return AlertResponse(alert=alert)


@router.get("/{alert_id}/evidence")
async def get_alert_evidence(
    alert_id: str,
    container: Container = Depends(get_container_dep),
    _: None = Depends(require_role("viewer")),
) -> dict[str, object]:
    evidence = container.uow.evidence.for_alert(alert_id)
    return {"alert_id": alert_id, "evidence": [e.model_dump(mode="json") for e in evidence]}


@router.get("/{alert_id}/audit")
async def get_alert_audit(
    alert_id: str,
    container: Container = Depends(get_container_dep),
    _: None = Depends(require_role("viewer")),
) -> dict[str, object]:
    return {"alert_id": alert_id, "events": container.uow.audit.for_alert(alert_id)}
