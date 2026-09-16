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

ELASTIC_SEVERITY = {
    "low": Severity.low,
    "medium": Severity.medium,
    "high": Severity.high,
    "critical": Severity.critical,
    "informational": Severity.informational,
}


class ElasticIngestor:
    source = AlertSource.elastic

    def parse(self, raw: dict[str, Any]) -> NormalizedAlert:
        if not isinstance(raw, dict):
            raise IngestionError("elastic document must be a JSON object")
        source = raw.get("_source") if isinstance(raw.get("_source"), dict) else raw
        if not isinstance(source, dict):
            raise IngestionError("elastic _source must be an object")
        event = source.get("event") or {}
        host = source.get("host") or {}
        user = source.get("user") or {}
        network = source.get("network") or {}
        process = source.get("process") or {}
        file_obj = source.get("file") or {}
        url_obj = source.get("url") or {}
        dns = source.get("dns") or {}
        rule = source.get("rule") or {}

        severity_raw = rule.get("severity") or event.get("severity")
        severity = ELASTIC_SEVERITY.get(
            str(severity_raw).lower() if severity_raw else "", Severity.medium
        )

        src_net = network.get("source") if isinstance(network, dict) else {}
        dst_net = network.get("destination") if isinstance(network, dict) else {}
        src_net = src_net if isinstance(src_net, dict) else {}
        dst_net = dst_net if isinstance(dst_net, dict) else {}
        file_hash_obj = file_obj.get("hash") if isinstance(file_obj, dict) else {}
        file_hash_obj = file_hash_obj if isinstance(file_hash_obj, dict) else {}
        dns_q = dns.get("question") if isinstance(dns, dict) else {}
        dns_q = dns_q if isinstance(dns_q, dict) else {}

        return NormalizedAlert(
            source=AlertSource.elastic,
            timestamp=parse_timestamp(source.get("@timestamp") or event.get("created")),
            rule_id=str(rule.get("id")) if rule.get("id") else None,
            rule_name=_first(rule.get("name"), event.get("action")),
            severity=severity,
            category=_first(rule.get("category"), event.get("category")),
            source_ip=_first(src_net.get("ip"), source.get("source_ip")),
            destination_ip=_first(dst_net.get("ip"), source.get("destination_ip")),
            source_port=safe_int(src_net.get("port")),
            destination_port=safe_int(dst_net.get("port")),
            protocol=_first(network.get("protocol"), source.get("network_protocol")),
            hostname=_first(host.get("hostname"), host.get("name"), source.get("hostname")),
            username=_first(user.get("name"), source.get("username")),
            process_name=_first(process.get("name"), process.get("executable")),
            command_line=process.get("command_line"),
            file_hash=_first(file_hash_obj.get("sha256"), file_hash_obj.get("md5")),
            domain=_first(dns_q.get("name"), source.get("domain")),
            url=_first(url_obj.get("full"), source.get("url")),
            raw_event=raw,
            metadata={
                "index": raw.get("_index"),
                "elastic_id": raw.get("_id"),
                "event_kind": event.get("kind"),
            },
        )

register_ingestor(ElasticIngestor())
