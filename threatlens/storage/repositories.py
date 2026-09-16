from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from threatlens.models.alerts import NormalizedAlert
from threatlens.models.evidence import Evidence, EvidenceType
from threatlens.models.triage import TriageResult
from threatlens.security.audit import AuditEvent
from threatlens.security.auth import tenant_id as current_tenant_id
from threatlens.storage.database import Database
from threatlens.storage.models import (
    AgentRunRow,
    AlertRow,
    AssetRow,
    AuditEventRow,
    EvidenceRow,
    LedgerEntryRow,
    ToolCallRow,
    TriageRow,
)


class AlertRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, alert: NormalizedAlert) -> None:
        with self._db.session() as s:
            existing = s.get(AlertRow, alert.id)
            tenant = current_tenant_id()
            if existing is not None and tenant is not None and existing.tenant_id != tenant:
                raise ValueError("alert belongs to another tenant")
            row = existing or AlertRow(id=alert.id, source=alert.source.value)
            row.tenant_id = tenant
            row.source = alert.source.value
            row.timestamp = alert.timestamp
            row.rule_id = alert.rule_id
            row.rule_name = alert.rule_name
            row.severity = alert.severity.value
            row.category = alert.category
            row.hostname = alert.hostname
            row.username = alert.username
            row.source_ip = alert.source_ip
            row.destination_ip = alert.destination_ip
            row.file_hash = alert.file_hash
            row.payload = alert.model_dump(mode="json")
            s.add(row)

    def get(self, alert_id: str) -> NormalizedAlert | None:
        stmt = select(AlertRow).where(AlertRow.id == alert_id)
        tenant = current_tenant_id()
        if tenant is not None:
            stmt = stmt.where(AlertRow.tenant_id == tenant)
        with self._db.session() as s:
            row = s.execute(stmt).scalar_one_or_none()
            if row is None:
                return None
            return NormalizedAlert.model_validate(row.payload)

    def query(
        self,
        *,
        hostname: str | None = None,
        username: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        file_hash: str | None = None,
        since: datetime | None = None,
        exclude_id: str | None = None,
        limit: int = 50,
    ) -> list[NormalizedAlert]:
        stmt = select(AlertRow)
        tenant = current_tenant_id()
        if tenant is not None:
            stmt = stmt.where(AlertRow.tenant_id == tenant)
        if hostname:
            stmt = stmt.where(AlertRow.hostname == hostname)
        if username:
            stmt = stmt.where(AlertRow.username == username)
        if source_ip:
            stmt = stmt.where(AlertRow.source_ip == source_ip)
        if destination_ip:
            stmt = stmt.where(AlertRow.destination_ip == destination_ip)
        if file_hash:
            stmt = stmt.where(AlertRow.file_hash == file_hash)
        if since:
            stmt = stmt.where(AlertRow.timestamp >= since)
        if exclude_id:
            stmt = stmt.where(AlertRow.id != exclude_id)
        stmt = stmt.order_by(AlertRow.timestamp.desc()).limit(limit)
        with self._db.session() as s:
            rows = s.execute(stmt).scalars().all()
            return [NormalizedAlert.model_validate(r.payload) for r in rows]

    def recent_for_hostname(self, hostname: str, hours: int = 24) -> list[NormalizedAlert]:
        since = datetime.now(UTC) - timedelta(hours=hours)
        return self.query(hostname=hostname, since=since)


class TriageRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, triage: TriageResult) -> None:
        with self._db.session() as s:
            row = TriageRow(
                triage_id=triage.triage_id,
                tenant_id=current_tenant_id(),
                alert_id=triage.alert_id,
                agent_run_id=triage.agent_run_id,
                classification=triage.classification.value,
                severity=triage.severity.value,
                confidence=triage.confidence,
                model_confidence=triage.model_confidence,
                requires_human_review=int(triage.requires_human_review),
                payload=triage.model_dump(mode="json"),
            )
            s.merge(row)
            for ev in triage.evidence:
                s.merge(
                    EvidenceRow(
                        id=ev.id,
                        tenant_id=current_tenant_id(),
                        triage_id=triage.triage_id,
                        alert_id=triage.alert_id,
                        source=ev.source,
                        type=ev.type.value,
                        finding=ev.finding,
                        confidence=ev.confidence,
                    )
                )

    def get(self, triage_id: str) -> TriageResult | None:
        stmt = select(TriageRow).where(TriageRow.triage_id == triage_id)
        tenant = current_tenant_id()
        if tenant is not None:
            stmt = stmt.where(TriageRow.tenant_id == tenant)
        with self._db.session() as s:
            row = s.execute(stmt).scalar_one_or_none()
            if row is None:
                return None
            return TriageResult.model_validate(row.payload)

    def list_for_alert(self, alert_id: str) -> list[TriageResult]:
        stmt = select(TriageRow).where(TriageRow.alert_id == alert_id)
        tenant = current_tenant_id()
        if tenant is not None:
            stmt = stmt.where(TriageRow.tenant_id == tenant)
        with self._db.session() as s:
            rows = s.execute(stmt).scalars().all()
            return [TriageResult.model_validate(r.payload) for r in rows]


class EvidenceRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def for_alert(self, alert_id: str) -> list[Evidence]:
        stmt = select(EvidenceRow).where(EvidenceRow.alert_id == alert_id)
        tenant = current_tenant_id()
        if tenant is not None:
            stmt = stmt.where(EvidenceRow.tenant_id == tenant)
        with self._db.session() as s:
            rows = s.execute(stmt).scalars().all()
            return [
                Evidence(
                    id=r.id,
                    source=r.source,
                    type=EvidenceType(r.type),
                    finding=r.finding,
                    confidence=r.confidence,
                )
                for r in rows
            ]


class AuditRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, event: AuditEvent) -> None:
        with self._db.session() as s:
            s.add(
                AuditEventRow(
                    id=event.id,
                    tenant_id=current_tenant_id(),
                    event_type=event.event_type,
                    alert_id=event.alert_id,
                    triage_id=event.triage_id,
                    agent_run_id=event.agent_run_id,
                    detail=event.redacted_detail(),
                    timestamp=event.timestamp,
                )
            )

    def for_alert(self, alert_id: str) -> list[dict[str, object]]:
        stmt = select(AuditEventRow).where(AuditEventRow.alert_id == alert_id)
        tenant = current_tenant_id()
        if tenant is not None:
            stmt = stmt.where(AuditEventRow.tenant_id == tenant)
        with self._db.session() as s:
            rows = s.execute(stmt).scalars().all()
            return [
                {
                    "id": r.id,
                    "event_type": r.event_type,
                    "timestamp": r.timestamp.isoformat(),
                    "detail": r.detail,
                }
                for r in rows
            ]


class LedgerRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(self, event: AuditEvent) -> None:
        if event.alert_id is None:
            return
        with self._db.session() as s:
            tenant = current_tenant_id()
            last = s.execute(
                select(LedgerEntryRow.sequence)
                .where(LedgerEntryRow.alert_id == event.alert_id)
                .where(LedgerEntryRow.tenant_id == tenant)
                .order_by(LedgerEntryRow.sequence.desc())
                .limit(1)
            ).scalar_one_or_none()
            s.add(
                LedgerEntryRow(
                    id=event.id,
                    tenant_id=tenant,
                    alert_id=event.alert_id,
                    triage_id=event.triage_id,
                    agent_run_id=event.agent_run_id,
                    sequence=(last or 0) + 1,
                    step_type=event.event_type,
                    payload=event.redacted_detail(),
                    timestamp=event.timestamp,
                )
            )

    def for_triage(self, triage_id: str, *, limit: int = 500) -> list[dict[str, object]]:
        tenant = current_tenant_id()
        triage_stmt = select(TriageRow.alert_id).where(TriageRow.triage_id == triage_id)
        if tenant is not None:
            triage_stmt = triage_stmt.where(TriageRow.tenant_id == tenant)
        with self._db.session() as s:
            alert_id = s.execute(triage_stmt).scalar_one_or_none()
            if alert_id is None:
                ledger_link = select(LedgerEntryRow.alert_id).where(
                    LedgerEntryRow.triage_id == triage_id
                )
                if tenant is not None:
                    ledger_link = ledger_link.where(LedgerEntryRow.tenant_id == tenant)
                alert_id = s.execute(ledger_link.limit(1)).scalar_one_or_none()
            if alert_id is None:
                return []
            stmt = select(LedgerEntryRow).where(LedgerEntryRow.alert_id == alert_id)
            if tenant is not None:
                stmt = stmt.where(LedgerEntryRow.tenant_id == tenant)
            stmt = stmt.order_by(LedgerEntryRow.sequence.asc()).limit(limit)
            rows = s.execute(stmt).scalars().all()
            return [
                {
                    "id": row.id,
                    "sequence": row.sequence,
                    "step_type": row.step_type,
                    "alert_id": row.alert_id,
                    "triage_id": row.triage_id,
                    "agent_run_id": row.agent_run_id,
                    "timestamp": row.timestamp.isoformat(),
                    "payload": row.payload,
                }
                for row in rows
            ]


class ToolCallRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(
        self,
        *,
        call_id: str,
        agent_run_id: str,
        alert_id: str,
        tool_name: str,
        arguments: dict[str, object],
        success: bool,
        latency_ms: float,
        result_summary: str | None,
    ) -> None:
        with self._db.session() as s:
            s.add(
                ToolCallRow(
                    id=call_id,
                    tenant_id=current_tenant_id(),
                    agent_run_id=agent_run_id,
                    alert_id=alert_id,
                    tool_name=tool_name,
                    arguments=arguments,
                    success=int(success),
                    latency_ms=latency_ms,
                    result_summary=result_summary,
                )
            )

    def for_alert(self, alert_id: str) -> list[dict[str, object]]:
        stmt = select(ToolCallRow).where(ToolCallRow.alert_id == alert_id)
        tenant = current_tenant_id()
        if tenant is not None:
            stmt = stmt.where(ToolCallRow.tenant_id == tenant)
        with self._db.session() as s:
            rows = s.execute(stmt).scalars().all()
            return [
                {
                    "id": row.id,
                    "tool_name": row.tool_name,
                    "arguments": row.arguments,
                    "success": bool(row.success),
                    "latency_ms": row.latency_ms,
                    "result_summary": row.result_summary,
                }
                for row in rows
            ]


class AgentRunRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(
        self, *, run_id: str, alert_id: str, final_state: str, payload: dict[str, object]
    ) -> None:
        with self._db.session() as s:
            s.merge(
                AgentRunRow(
                    id=run_id,
                    tenant_id=current_tenant_id(),
                    alert_id=alert_id,
                    final_state=final_state,
                    payload=payload,
                )
            )


class AssetRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def upsert(
        self,
        *,
        hostname: str,
        asset_type: str,
        environment: str,
        owner: str | None,
        criticality: str,
        department: str | None,
        role: str | None,
        ip_addresses: list[str],
        operating_system: str | None,
    ) -> None:
        with self._db.session() as s:
            s.merge(
                AssetRow(
                    hostname=hostname,
                    asset_type=asset_type,
                    environment=environment,
                    owner=owner,
                    criticality=criticality,
                    department=department,
                    role=role,
                    ip_addresses=ip_addresses,
                    operating_system=operating_system,
                )
            )

    def get(self, hostname: str) -> AssetRow | None:
        with self._db.session() as s:
            return s.get(AssetRow, hostname)


class UnitOfWork:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.alerts = AlertRepository(db)
        self.triage = TriageRepository(db)
        self.evidence = EvidenceRepository(db)
        self.audit = AuditRepository(db)
        self.ledger = LedgerRepository(db)
        self.tool_calls = ToolCallRepository(db)
        self.agent_runs = AgentRunRepository(db)
        self.assets = AssetRepository(db)
