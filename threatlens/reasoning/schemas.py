from __future__ import annotations

from pydantic import BaseModel, Field

from threatlens.models.evidence import Evidence


class EvidenceBundle(BaseModel):
    evidence: list[Evidence] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    signals: dict[str, object] = Field(default_factory=dict)

    def by_id(self, evidence_id: str) -> Evidence | None:
        for ev in self.evidence:
            if ev.id == evidence_id:
                return ev
        return None

    def ids(self) -> list[str]:
        return [e.id for e in self.evidence]
