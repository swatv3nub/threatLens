from __future__ import annotations

import hashlib

from threatlens.models.alerts import NormalizedAlert
from threatlens.models.enrichment import EnrichmentContext
from threatlens.models.evidence import Evidence, EvidenceType
from threatlens.reasoning.schemas import EvidenceBundle


def _stable_id(*parts: object) -> str:
    """Deterministic evidence ID.

    Evidence must be citable by a stable identifier so that the IDs returned by
    the reasoning model resolve back to the same objects on every build (and
    across replays). Random IDs broke evidence grounding: the model referenced
    IDs from one build while the agent re-built a second, differently-identified
    set.
    """
    key = "|".join(str(p) for p in parts)
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:8].upper()
    return f"EVID-{digest}"


class EvidenceBuilder:
    """Turns raw enrichment into first-class, citable evidence objects."""

    def build(self, alert: NormalizedAlert, ctx: EnrichmentContext) -> EvidenceBundle:
        evidence: list[Evidence] = []
        observations: list[str] = []

        malicious_indicator = False
        benign_indicator = False

        for ip_rep in ctx.ip_reputations:
            label = f"{ip_rep.ip} ({ip_rep.source})"
            if ip_rep.malicious:
                malicious_indicator = True
                evidence.append(
                    Evidence(
                        id=_stable_id("ip", ip_rep.source, ip_rep.ip),
                        source=ip_rep.source,
                        type=EvidenceType.reputation,
                        finding=(
                            f"IP {label} flagged malicious with abuse confidence "
                            f"{ip_rep.confidence_score}/100 ({ip_rep.total_reports} reports)"
                        ),
                        confidence=min(0.99, 0.6 + ip_rep.confidence_score / 250),
                        timestamp=ip_rep.last_reported_at,
                        raw_reference=f"ip:{ip_rep.ip}",
                    )
                )
                observations.append(f"IP {label} has high reputation risk.")
            elif ip_rep.known_benign:
                benign_indicator = True
                evidence.append(
                    Evidence(
                        id=_stable_id("ip", ip_rep.source, ip_rep.ip),
                        source=ip_rep.source,
                        type=EvidenceType.reputation,
                        finding=(
                            f"IP {label} is a recognized infrastructure address "
                            f"(score {ip_rep.confidence_score}/100)"
                        ),
                        confidence=0.6,
                        raw_reference=f"ip:{ip_rep.ip}",
                    )
                )
                observations.append(f"IP {label} is recognized infrastructure.")
            else:
                evidence.append(
                    Evidence(
                        id=_stable_id("ip", ip_rep.source, ip_rep.ip),
                        source=ip_rep.source,
                        type=EvidenceType.reputation,
                        finding=(
                            f"IP {label} has no reputation history "
                            f"(score {ip_rep.confidence_score}/100)"
                        ),
                        confidence=0.3,
                        raw_reference=f"ip:{ip_rep.ip}",
                    )
                )

        for domain_rep in ctx.domain_reputations:
            if domain_rep.malicious:
                evidence.append(
                    Evidence(
                        id=_stable_id("domain", domain_rep.source, domain_rep.domain),
                        source=domain_rep.source,
                        type=EvidenceType.reputation,
                        finding=(
                            f"Domain {domain_rep.domain} flagged malicious "
                            f"(score {domain_rep.reputation_score}/100)"
                        ),
                        confidence=0.85,
                        raw_reference=f"domain:{domain_rep.domain}",
                    )
                )
                observations.append(f"Domain {domain_rep.domain} is malicious.")
                malicious_indicator = True
            elif domain_rep.known_benign:
                benign_indicator = True
                evidence.append(
                    Evidence(
                        id=_stable_id("domain", domain_rep.source, domain_rep.domain),
                        source=domain_rep.source,
                        type=EvidenceType.reputation,
                        finding=(
                            f"Domain {domain_rep.domain} is a recognized benign domain"
                        ),
                        confidence=0.6,
                        raw_reference=f"domain:{domain_rep.domain}",
                    )
                )
            else:
                evidence.append(
                    Evidence(
                        id=_stable_id("domain", domain_rep.source, domain_rep.domain),
                        source=domain_rep.source,
                        type=EvidenceType.reputation,
                        finding=f"Domain {domain_rep.domain} has no reputation history",
                        confidence=0.3,
                        raw_reference=f"domain:{domain_rep.domain}",
                    )
                )

        for file_rep in ctx.file_reputations:
            if file_rep.malicious:
                evidence.append(
                    Evidence(
                        id=_stable_id("file", file_rep.source, file_rep.file_hash),
                        source=file_rep.source,
                        type=EvidenceType.reputation,
                        finding=(
                            f"File {file_rep.file_hash[:16]}... detected by "
                            f"{file_rep.detections}/{file_rep.total_engines} engines"
                        ),
                        confidence=0.95,
                        raw_reference=f"file:{file_rep.file_hash}",
                    )
                )
                observations.append("File hash is known malicious.")
                malicious_indicator = True

        for url_rep in ctx.url_reputations:
            if url_rep.malicious:
                evidence.append(
                    Evidence(
                        id=_stable_id("url", url_rep.source, url_rep.url),
                        source=url_rep.source,
                        type=EvidenceType.reputation,
                        finding=f"URL {url_rep.url} flagged malicious",
                        confidence=0.85,
                        raw_reference=f"url:{url_rep.url}",
                    )
                )
                malicious_indicator = True

        asset_critical = False
        for asset in ctx.assets:
            critical = asset.criticality.lower() in {"critical", "high"}
            asset_critical = asset_critical or asset.criticality.lower() == "critical"
            evidence.append(
                Evidence(
                    id=_stable_id("asset", asset.hostname),
                    source="asset_context",
                    type=EvidenceType.asset,
                    finding=(
                        f"Asset {asset.hostname} is {asset.environment} "
                        f"{asset.criticality} ({asset.role})"
                    ),
                    confidence=0.95,
                    raw_reference=f"asset:{asset.hostname}",
                )
            )
            observations.append(
                f"Asset {asset.hostname} is {asset.criticality} {asset.environment}."
            )
            if critical:
                observations.append(f"Asset {asset.hostname} is high-value.")

        rapid_repeat = 0
        for hist in ctx.history:
            if hist.count > 0:
                rapid_repeat += hist.count
                evidence.append(
                    Evidence(
                        id=_stable_id("history", hist.query),
                        source="alert_history",
                        type=EvidenceType.history,
                        finding=f"{hist.count} prior alerts for {hist.query}",
                        confidence=0.7,
                        raw_reference=hist.query,
                    )
                )
                observations.append(f"{hist.count} prior alerts matched {hist.query}.")

        for tech in ctx.mitre_techniques:
            evidence.append(
                Evidence(
                    id=_stable_id("mitre", tech.technique_id),
                    source="mitre_attack",
                    type=EvidenceType.mitre,
                    finding=f"{tech.technique_id} {tech.technique_name} ({tech.tactic})",
                    confidence=tech.confidence,
                    raw_reference=f"mitre:{tech.technique_id}",
                )
            )

        for missing in ctx.missing_context:
            evidence.append(
                Evidence(
                    id=_stable_id("missing", missing),
                    source="enrichment",
                    type=EvidenceType.static,
                    finding=f"Missing context: {missing}",
                    confidence=0.3,
                )
            )

        signals: dict[str, object] = {
            "malicious_indicator": malicious_indicator,
            "benign_indicator": benign_indicator and not malicious_indicator,
            "asset_critical": asset_critical,
            "rapid_repeat_count": rapid_repeat,
            "degraded": ctx.degraded,
            "missing_asset": any("asset" in m.lower() for m in ctx.missing_context),
            "has_mitre": bool(ctx.mitre_techniques),
        }
        return EvidenceBundle(evidence=evidence, observations=observations, signals=signals)
