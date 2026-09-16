from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class IPReputation(BaseModel):
    ip: str
    malicious: bool = False
    known_benign: bool = False
    confidence_score: int = Field(default=0, ge=0, le=100)
    country: str | None = None
    isp: str | None = None
    usage_type: str | None = None
    domain: str | None = None
    total_reports: int = 0
    last_reported_at: datetime | None = None
    source: str = "unknown"
    raw: dict[str, Any] = Field(default_factory=dict)


class DomainReputation(BaseModel):
    domain: str
    malicious: bool = False
    known_benign: bool = False
    reputation_score: int = Field(default=0, ge=0, le=100)
    categories: list[str] = Field(default_factory=list)
    registrar: str | None = None
    source: str = "unknown"
    raw: dict[str, Any] = Field(default_factory=dict)


class FileReputation(BaseModel):
    file_hash: str
    malicious: bool = False
    detections: int = 0
    total_engines: int = 0
    threat_labels: list[str] = Field(default_factory=list)
    source: str = "unknown"
    raw: dict[str, Any] = Field(default_factory=dict)


class URLReputation(BaseModel):
    url: str
    malicious: bool = False
    detections: int = 0
    total_engines: int = 0
    categories: list[str] = Field(default_factory=list)
    source: str = "unknown"
    raw: dict[str, Any] = Field(default_factory=dict)


class AssetContext(BaseModel):
    hostname: str
    asset_type: str = "unknown"
    environment: str = "unknown"
    owner: str | None = None
    criticality: str = "unknown"
    department: str | None = None
    role: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    operating_system: str | None = None
    found: bool = True


class HistoricalAlert(BaseModel):
    alert_id: str
    timestamp: datetime
    rule_name: str | None = None
    severity: str = "informational"
    source: str = "unknown"


class HistoricalContext(BaseModel):
    query: str
    window_hours: int
    matches: list[HistoricalAlert] = Field(default_factory=list)
    count: int = 0


class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence: str | None = None


class EnrichmentContext(BaseModel):
    ip_reputations: list[IPReputation] = Field(default_factory=list)
    domain_reputations: list[DomainReputation] = Field(default_factory=list)
    file_reputations: list[FileReputation] = Field(default_factory=list)
    url_reputations: list[URLReputation] = Field(default_factory=list)
    assets: list[AssetContext] = Field(default_factory=list)
    history: list[HistoricalContext] = Field(default_factory=list)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    tool_errors: list[str] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)
    degraded: bool = False

    def is_empty(self) -> bool:
        return not any(
            [
                self.ip_reputations,
                self.domain_reputations,
                self.file_reputations,
                self.url_reputations,
                self.assets,
                self.history,
                self.mitre_techniques,
            ]
        )
