from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from threatlens.security.validation import (
    is_valid_domain,
    is_valid_hash,
    is_valid_hostname,
    is_valid_ip,
    is_valid_sha256_or_md5,
)


class Severity(str, Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.informational: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


def max_severity(a: Severity, b: Severity) -> Severity:
    return a if SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] else b


class AlertSource(str, Enum):
    wazuh = "wazuh"
    suricata = "suricata"
    elastic = "elastic"
    synthetic = "synthetic"


class NormalizedAlert(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    source: AlertSource
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    rule_id: str | None = None
    rule_name: str | None = None
    severity: Severity = Severity.informational
    category: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    hostname: str | None = None
    username: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    file_hash: str | None = None
    domain: str | None = None
    url: str | None = None
    raw_event: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def _validate_ip(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not is_valid_ip(v):
            raise ValueError(f"invalid IP address: {v!r}")
        return v

    @field_validator("file_hash")
    @classmethod
    def _validate_hash(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not is_valid_hash(v):
            raise ValueError(f"invalid file hash: {v!r}")
        return v

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not is_valid_domain(v):
            raise ValueError(f"invalid domain: {v!r}")
        return v

    @field_validator("hostname")
    @classmethod
    def _validate_hostname(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not is_valid_hostname(v):
            raise ValueError(f"invalid hostname: {v!r}")
        return v

    def indicators(self) -> dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "domain": self.domain,
            "url": self.url,
            "file_hash": self.file_hash,
            "hostname": self.hostname,
            "username": self.username,
            "process_name": self.process_name,
            "command_line": self.command_line,
        }

    def has_network_indicator(self) -> bool:
        return bool(self.source_ip or self.destination_ip)

    def is_hash_valid(self) -> bool:
        return bool(self.file_hash and is_valid_sha256_or_md5(self.file_hash))
