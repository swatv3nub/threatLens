from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class EvidenceType(str, Enum):
    reputation = "reputation"
    asset = "asset"
    history = "history"
    mitre = "mitre"
    static = "static"
    policy = "policy"


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: f"EVID-{uuid4().hex[:8].upper()}")
    source: str
    type: EvidenceType
    finding: str
    confidence: float = Field(ge=0.0, le=1.0)
    timestamp: datetime | None = None
    raw_reference: str | None = None
