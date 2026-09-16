from __future__ import annotations

from typing import Any

from threatlens.ingestion.base import (
    IngestionError,
    _first,
    parse_timestamp,
    register_ingestor,
    safe_int,
)
from threatlens.models.alerts import AlertSource, NormalizedAlert, Severity

WAZUH_LEVEL_TO_SEVERITY = {
    range(0, 4): Severity.informational,
    range(4, 8): Severity.low,
    range(8, 11): Severity.medium,
    range(11, 14): Severity.high,
    range(14, 16): Severity.critical,
}


def _severity_from_level(level: int | None) -> Severity:
    if level is None:
        return Severity.informational
    for rng, sev in WAZUH_LEVEL_TO_SEVERITY.items():
        if level in rng:
            return sev
    return Severity.critical if level >= 14 else Severity.informational


class WazuhIngestor:
    source = AlertSource.wazuh

    def parse(self, raw: dict[str, Any]) -> NormalizedAlert:
        if not isinstance(raw, dict):
            raise IngestionError("wazuh alert must be a JSON object")
        rule = raw.get("rule") or {}
        agent = raw.get("agent") or {}
        data = raw.get("data") or {}
        if not isinstance(rule, dict) or not isinstance(data, dict):
            raise IngestionError("wazuh rule/data must be objects")

        timestamp = parse_timestamp(raw.get("timestamp"))
        level = rule.get("level")
        try:
            level_int = int(level) if level is not None else None
        except (TypeError, ValueError):
            level_int = None

        command_line = _first(
            data.get("command"),
            data.get("commandLine"),
            (data.get("win") or {}).get("eventdata", {}).get("commandLine")
            if isinstance(data.get("win"), dict)
            else None,
        )
        groups = rule.get("groups")
        category = groups[0] if isinstance(groups, list) and groups else None

        return NormalizedAlert(
            source=AlertSource.wazuh,
            timestamp=timestamp,
            rule_id=str(rule.get("id")) if rule.get("id") is not None else None,
            rule_name=rule.get("description"),
            severity=_severity_from_level(level_int),
            category=category,
            source_ip=_first(data.get("srcip"), data.get("src_ip")),
            destination_ip=_first(data.get("dstip"), data.get("dst_ip")),
            source_port=safe_int(data.get("srcport")),
            destination_port=safe_int(data.get("dstport")),
            protocol=data.get("protocol"),
            hostname=_first(agent.get("name"), raw.get("hostname")),
            username=_first(data.get("srcuser"), data.get("dstuser")),
            process_name=_first(data.get("process"), data.get("program_name")),
            command_line=command_line,
            file_hash=_first(data.get("md5"), data.get("sha256"), data.get("sha1")),
            domain=_first(data.get("domain"), data.get("dns_query")),
            url=data.get("url"),
            raw_event=raw,
            metadata={"wazuh_level": level_int, "decoder": raw.get("decoder")},
        )

register_ingestor(WazuhIngestor())
