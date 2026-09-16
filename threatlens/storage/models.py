from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class AlertRow(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    rule_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    severity: Mapped[str] = mapped_column(String(16))
    category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(256), index=True, nullable=True)
    username: Mapped[str | None] = mapped_column(String(256), index=True, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class TriageRow(Base):
    __tablename__ = "triage_results"

    triage_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    alert_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_run_id: Mapped[str] = mapped_column(String(64), index=True)
    classification: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    model_confidence: Mapped[float] = mapped_column(Float)
    requires_human_review: Mapped[int] = mapped_column(Integer, default=1)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class EvidenceRow(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    triage_id: Mapped[str] = mapped_column(String(64), index=True)
    alert_id: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(64))
    type: Mapped[str] = mapped_column(String(32))
    finding: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)


class ToolCallRow(Base):
    __tablename__ = "tool_calls"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    agent_run_id: Mapped[str] = mapped_column(String(64), index=True)
    alert_id: Mapped[str] = mapped_column(String(64), index=True)
    tool_name: Mapped[str] = mapped_column(String(64))
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    success: Mapped[int] = mapped_column(Integer, default=1)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AuditEventRow(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    alert_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    triage_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    agent_run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class LedgerEntryRow(Base):
    __tablename__ = "investigation_ledger"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    alert_id: Mapped[str] = mapped_column(String(64), index=True)
    triage_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    agent_run_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    sequence: Mapped[int] = mapped_column(Integer, index=True)
    step_type: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AssetRow(Base):
    __tablename__ = "assets"

    hostname: Mapped[str] = mapped_column(String(256), primary_key=True)
    asset_type: Mapped[str] = mapped_column(String(64))
    environment: Mapped[str] = mapped_column(String(32))
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    criticality: Mapped[str] = mapped_column(String(32))
    department: Mapped[str | None] = mapped_column(String(128), nullable=True)
    role: Mapped[str | None] = mapped_column(String(256), nullable=True)
    ip_addresses: Mapped[list[str]] = mapped_column(JSON, default=list)
    operating_system: Mapped[str | None] = mapped_column(String(128), nullable=True)
