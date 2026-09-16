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

SURICATA_SEVERITY = {
    1: Severity.critical,
    2: Severity.high,
    3: Severity.medium,
    4: Severity.low,
}


class SuricataIngestor:
    source = AlertSource.suricata

    def parse(self, raw: dict[str, Any]) -> NormalizedAlert:
        if not isinstance(raw, dict):
            raise IngestionError("suricata event must be a JSON object")
        if raw.get("event_type") not in (None, "alert"):
            raise IngestionError(f"unsupported suricata event_type: {raw.get('event_type')!r}")
        alert = raw.get("alert") or {}
        if not isinstance(alert, dict):
            raise IngestionError("suricata alert must be an object")
        dns = raw.get("dns") or {}
        http = raw.get("http") or {}
        tls = raw.get("tls") or {}

        severity_code = safe_int(alert.get("severity"))
        severity = (
            SURICATA_SEVERITY.get(severity_code, Severity.medium)
            if severity_code is not None
            else Severity.medium
        )
        domain = None
        if isinstance(dns, dict):
            domain = _first(dns.get("rrname"), dns.get("query"))
        elif isinstance(tls, dict):
            domain = tls.get("sni")

        return NormalizedAlert(
            source=AlertSource.suricata,
            timestamp=parse_timestamp(raw.get("timestamp")),
            rule_id=str(alert.get("signature_id")) if alert.get("signature_id") else None,
            rule_name=alert.get("signature"),
            severity=severity,
            category=alert.get("category"),
            source_ip=raw.get("src_ip"),
            destination_ip=raw.get("dest_ip"),
            source_port=safe_int(raw.get("src_port")),
            destination_port=safe_int(raw.get("dest_port")),
            protocol=_first(raw.get("proto"), raw.get("app_proto")),
            hostname=raw.get("host"),
            url=http.get("url") if isinstance(http, dict) else None,
            domain=domain,
            raw_event=raw,
            metadata={
                "action": alert.get("action"),
                "flow_id": raw.get("flow_id"),
                "http_method": http.get("http_method") if isinstance(http, dict) else None,
            },
        )

register_ingestor(SuricataIngestor())
