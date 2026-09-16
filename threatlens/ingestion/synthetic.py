from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from threatlens.ingestion.base import IngestionError, parse_timestamp, register_ingestor
from threatlens.models.alerts import AlertSource, NormalizedAlert, Severity

MALICIOUS_IP = "203.0.113.66"
SECOND_MALICIOUS_IP = "198.51.100.23"
MALICIOUS_HASH = "44d88612fea8a8f36de82e1278abb02f" + "0" * 32
BENIGN_SCANNER_IP = "192.0.2.50"
BENIGN_MONITORING_IP = "10.0.0.77"
SUSPICIOUS_DOMAIN = "evil-c2.example.invalid"
BENIGN_DOMAIN = "updates.example.com"


class SyntheticIngestor:
    source = AlertSource.synthetic

    def parse(self, raw: dict[str, Any]) -> NormalizedAlert:
        if not isinstance(raw, dict):
            raise IngestionError("synthetic alert must be a JSON object")
        alert = NormalizedAlert(
            source=AlertSource.synthetic,
            id=raw.get("id") or NormalizedAlert(source=AlertSource.synthetic).id,
            timestamp=parse_timestamp(raw.get("timestamp")),
            rule_id=raw.get("rule_id"),
            rule_name=raw.get("rule_name") or raw.get("name"),
            severity=_severity(raw.get("severity")),
            category=raw.get("category"),
            source_ip=raw.get("source_ip"),
            destination_ip=raw.get("destination_ip"),
            source_port=raw.get("source_port"),
            destination_port=raw.get("destination_port"),
            protocol=raw.get("protocol"),
            hostname=raw.get("hostname"),
            username=raw.get("username"),
            process_name=raw.get("process_name"),
            command_line=raw.get("command_line"),
            file_hash=raw.get("file_hash"),
            domain=raw.get("domain"),
            url=raw.get("url"),
            raw_event=raw,
            metadata=raw.get("metadata") or {},
        )
        return alert

def _severity(value: Any) -> Severity:
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.medium


def load_synthetic(path: str | Path) -> NormalizedAlert:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        raise IngestionError("expected a single synthetic alert object")
    return SyntheticIngestor().parse(data)


def generate_scenarios(now: datetime | None = None) -> list[dict[str, Any]]:
    base = now or datetime.now(UTC)
    scenarios: list[dict[str, Any]] = [
        {
            "id": "syn-001",
            "rule_name": "Outbound connection to known malicious IP",
            "severity": "high",
            "category": "command_and_control",
            "source_ip": "10.1.20.15",
            "destination_ip": MALICIOUS_IP,
            "destination_port": 8443,
            "protocol": "tcp",
            "hostname": "payments-prod-01",
            "timestamp": (base - timedelta(minutes=5)).isoformat(),
        },
        {
            "id": "syn-002",
            "rule_name": "Suspicious PowerShell execution",
            "severity": "high",
            "category": "execution",
            "hostname": "workstation-fin-07",
            "username": "j.doe",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA",
            "timestamp": (base - timedelta(minutes=12)).isoformat(),
        },
        {
            "id": "syn-003",
            "rule_name": "Known malicious file hash detected",
            "severity": "critical",
            "category": "malware",
            "hostname": "fileserver-02",
            "file_hash": MALICIOUS_HASH,
            "process_name": "svchost.exe",
            "timestamp": (base - timedelta(minutes=30)).isoformat(),
        },
        {
            "id": "syn-004",
            "rule_name": "Failed login brute force",
            "severity": "medium",
            "category": "authentication",
            "source_ip": SECOND_MALICIOUS_IP,
            "destination_ip": "10.1.10.5",
            "hostname": "vpn-gateway-01",
            "username": "administrator",
            "timestamp": (base - timedelta(minutes=8)).isoformat(),
        },
        {
            "id": "syn-005",
            "rule_name": "Suspicious DNS query",
            "severity": "medium",
            "category": "dns",
            "hostname": "workstation-hr-03",
            "source_ip": "10.1.30.22",
            "domain": SUSPICIOUS_DOMAIN,
            "destination_port": 53,
            "protocol": "udp",
            "timestamp": (base - timedelta(minutes=3)).isoformat(),
        },
        {
            "id": "syn-006",
            "rule_name": "Vulnerability scanner activity",
            "severity": "low",
            "category": "scanning",
            "source_ip": BENIGN_SCANNER_IP,
            "destination_ip": "10.1.10.10",
            "hostname": "scan-runner-01",
            "timestamp": (base - timedelta(minutes=45)).isoformat(),
        },
        {
            "id": "syn-007",
            "rule_name": "Internal monitoring healthcheck",
            "severity": "informational",
            "category": "monitoring",
            "source_ip": BENIGN_MONITORING_IP,
            "destination_ip": "10.1.10.20",
            "hostname": "monitor-01",
            "domain": BENIGN_DOMAIN,
            "timestamp": (base - timedelta(minutes=1)).isoformat(),
        },
        {
            "id": "syn-008",
            "rule_name": "Lateral movement via SMB",
            "severity": "high",
            "category": "lateral_movement",
            "source_ip": "10.1.20.31",
            "destination_ip": "10.1.20.99",
            "hostname": "workstation-eng-11",
            "username": "svc_backup",
            "process_name": "psexesvc.exe",
            "destination_port": 445,
            "protocol": "tcp",
            "timestamp": (base - timedelta(minutes=20)).isoformat(),
        },
        {
            "id": "syn-009",
            "rule_name": "Suspicious web request",
            "severity": "medium",
            "category": "web",
            "hostname": "web-proxy-01",
            "source_ip": "10.1.40.18",
            "url": f"http://{SUSPICIOUS_DOMAIN}/payload.bin",
            "domain": SUSPICIOUS_DOMAIN,
            "protocol": "http",
            "timestamp": (base - timedelta(minutes=6)).isoformat(),
        },
        {
            "id": "syn-010",
            "rule_name": "Ambiguous authentication anomaly",
            "severity": "medium",
            "category": "authentication",
            "hostname": "workstation-mkt-04",
            "username": "a.smith",
            "source_ip": "10.1.50.44",
            "timestamp": (base - timedelta(minutes=15)).isoformat(),
        },
    ]
    return scenarios


def write_scenarios(directory: str | Path) -> list[Path]:
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for scenario in generate_scenarios():
        path = out_dir / f"{scenario['id']}.json"
        path.write_text(json.dumps(scenario, indent=2), encoding="utf-8")
        paths.append(path)
    return paths


register_ingestor(SyntheticIngestor())
