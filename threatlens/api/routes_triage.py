from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from threatlens.api.dependencies import enforce_rate_limit, get_container_dep, require_role
from threatlens.api.schemas import TriageRequest, TriageResponse
from threatlens.container import Container
from threatlens.ingestion.base import IngestionError, parse_alert
from threatlens.models.alerts import NormalizedAlert
from threatlens.models.triage import TriageResult

router = APIRouter(prefix="/api/v1/triage", tags=["triage"])


def _to_response(triage: TriageResult) -> TriageResponse:
    return TriageResponse(
        triage_id=triage.triage_id,
        alert_id=triage.alert_id,
        agent_run_id=triage.agent_run_id,
        classification=triage.classification,
        severity=triage.severity,
        confidence=triage.confidence,
        model_confidence=triage.model_confidence,
        summary=triage.summary,
        evidence=[e.model_dump(mode="json") for e in triage.evidence],
        recommended_actions=triage.recommended_actions,
        mitre_attack=triage.mitre_attack,
        uncertainties=triage.uncertainties,
        requires_human_review=triage.requires_human_review,
        action_executed=triage.action_executed,
        policy_adjustments=triage.policy_adjustments,
        tool_call_count=triage.tool_call_count,
    )


def _normalize_request(request: TriageRequest) -> NormalizedAlert:
    """Resolve a request into a NormalizedAlert.

    Explicitly documented precedence: `normalized=true` wins; otherwise an alert
    that already looks normalized (contains a `source` field) is parsed as such;
    otherwise an ingestor is selected by the `source` discriminator.
    """
    looks_normalized = request.normalized or (
        request.source is None and "source" in request.alert
    )
    if looks_normalized:
        return NormalizedAlert.model_validate(request.alert)
    if request.source is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="source is required unless the alert is already normalized",
        )
    return parse_alert(request.source, request.alert)


@router.post("", response_model=TriageResponse, status_code=status.HTTP_201_CREATED)
async def create_triage(
    request: TriageRequest,
    container: Container = Depends(get_container_dep),
    _: None = Depends(enforce_rate_limit),
    __: None = Depends(require_role("analyst")),
) -> TriageResponse:
    try:
        alert = _normalize_request(request)
    except HTTPException:
        raise
    except IngestionError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    container.uow.alerts.save(alert)
    container.audit.emit("alert_ingested", alert_id=alert.id)
    triage = await container.agent.run(alert)
    container.uow.triage.save(triage)
    return _to_response(triage)


@router.get("/{triage_id}", response_model=TriageResponse)
async def get_triage(
    triage_id: str,
    container: Container = Depends(get_container_dep),
    _: None = Depends(require_role("viewer")),
) -> TriageResponse:
    triage = container.uow.triage.get(triage_id)
    if triage is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="triage not found"
        )
    return _to_response(triage)
