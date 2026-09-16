from __future__ import annotations

import pytest

from threatlens.ingestion.base import IngestionError, parse_alert
from threatlens.ingestion.elastic import ElasticIngestor
from threatlens.ingestion.suricata import SuricataIngestor
from threatlens.ingestion.synthetic import SyntheticIngestor
from threatlens.ingestion.wazuh import WazuhIngestor
from threatlens.models.alerts import Severity


def test_wazuh_parsing() -> None:
    raw = {
        "timestamp": "2026-09-16T10:15:00.000Z",
        "rule": {"id": "5710", "level": 12, "description": "auth failures"},
        "agent": {"name": "vpn-gateway-01"},
        "data": {"srcip": "198.51.100.23", "dstuser": "administrator"},
    }
    alert = WazuhIngestor().parse(raw)
    assert alert.source.value == "wazuh"
    assert alert.severity == Severity.high
    assert alert.source_ip == "198.51.100.23"
    assert alert.hostname == "vpn-gateway-01"


def test_suricata_parsing() -> None:
    raw = {
        "timestamp": "2026-09-16T10:20:00.000Z",
        "event_type": "alert",
        "src_ip": "10.1.20.15",
        "dest_ip": "203.0.113.66",
        "proto": "TCP",
        "alert": {
            "signature_id": 2010935,
            "signature": "ET MALWARE Known C2 Beacon",
            "severity": 1,
        },
    }
    alert = SuricataIngestor().parse(raw)
    assert alert.severity == Severity.critical
    assert alert.destination_ip == "203.0.113.66"
    assert alert.rule_id == "2010935"


def test_elastic_parsing() -> None:
    raw = {
        "_source": {
            "@timestamp": "2026-09-16T10:25:00.000Z",
            "event": {"kind": "alert", "severity": "high"},
            "rule": {"name": "Encoded PowerShell"},
            "host": {"hostname": "workstation-fin-07"},
            "user": {"name": "j.doe"},
            "process": {"name": "powershell.exe", "command_line": "powershell -enc AAAA"},
        }
    }
    alert = ElasticIngestor().parse(raw)
    assert alert.hostname == "workstation-fin-07"
    assert alert.severity == Severity.high
    assert "powershell" in (alert.command_line or "")


def test_synthetic_rejects_non_dict() -> None:
    with pytest.raises(IngestionError):
        SyntheticIngestor().parse(["not", "a", "dict"])  # type: ignore[arg-type]


def test_parse_alert_dispatch() -> None:
    alert = parse_alert("synthetic", {"id": "x", "rule_name": "r", "severity": "low"})
    assert alert.id == "x"
    assert alert.severity == Severity.low
