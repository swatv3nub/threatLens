from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from threatlens.models.alerts import Severity
from threatlens.models.reasoning import Classification


class EvaluationCase(BaseModel):
    id: str
    alert: dict[str, Any]
    expected_classification: Classification
    expected_severity: Severity
    tags: list[str] = Field(default_factory=list)


EVALUATION_CASES: list[dict[str, Any]] = [
    {
        "id": "eval-001",
        "alert": {
            "id": "eval-001",
            "rule_name": "Outbound connection to known malicious IP",
            "severity": "high",
            "category": "command_and_control",
            "source_ip": "10.1.20.15",
            "destination_ip": "203.0.113.66",
            "destination_port": 8443,
            "protocol": "tcp",
            "hostname": "payments-prod-01",
        },
        "expected_classification": "true_positive",
        "expected_severity": "critical",
        "tags": ["malicious_ip", "critical_asset"],
    },
    {
        "id": "eval-002",
        "alert": {
            "id": "eval-002",
            "rule_name": "Suspicious PowerShell execution",
            "severity": "high",
            "category": "execution",
            "hostname": "workstation-fin-07",
            "username": "j.doe",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA",
        },
        "expected_classification": "needs_investigation",
        "expected_severity": "medium",
        "tags": ["powershell"],
    },
    {
        "id": "eval-003",
        "alert": {
            "id": "eval-003",
            "rule_name": "Known malicious file hash detected",
            "severity": "critical",
            "category": "malware",
            "hostname": "fileserver-02",
            "file_hash": "44d88612fea8a8f36de82e1278abb02f" + "0" * 32,
            "process_name": "svchost.exe",
        },
        "expected_classification": "true_positive",
        "expected_severity": "high",
        "tags": ["malicious_hash"],
    },
    {
        "id": "eval-004",
        "alert": {
            "id": "eval-004",
            "rule_name": "Vulnerability scanner activity",
            "severity": "low",
            "category": "scanning",
            "source_ip": "192.0.2.50",
            "destination_ip": "10.1.10.10",
            "hostname": "scan-runner-01",
        },
        "expected_classification": "false_positive",
        "expected_severity": "low",
        "tags": ["benign_scanner"],
    },
    {
        "id": "eval-005",
        "alert": {
            "id": "eval-005",
            "rule_name": "Internal monitoring healthcheck",
            "severity": "informational",
            "category": "monitoring",
            "source_ip": "10.0.0.77",
            "destination_ip": "10.1.10.20",
            "hostname": "monitor-01",
            "domain": "updates.example.com",
        },
        "expected_classification": "false_positive",
        "expected_severity": "low",
        "tags": ["benign_monitoring"],
    },
    {
        "id": "eval-006",
        "alert": {
            "id": "eval-006",
            "rule_name": "Suspicious DNS query",
            "severity": "medium",
            "category": "dns",
            "hostname": "workstation-hr-03",
            "source_ip": "10.1.30.22",
            "domain": "evil-c2.example.invalid",
            "destination_port": 53,
            "protocol": "udp",
        },
        "expected_classification": "true_positive",
        "expected_severity": "high",
        "tags": ["malicious_domain"],
    },
    {
        "id": "eval-007",
        "alert": {
            "id": "eval-007",
            "rule_name": "Failed login brute force",
            "severity": "medium",
            "category": "authentication",
            "source_ip": "198.51.100.23",
            "destination_ip": "10.1.10.5",
            "hostname": "vpn-gateway-01",
            "username": "administrator",
        },
        "expected_classification": "true_positive",
        "expected_severity": "critical",
        "tags": ["brute_force", "critical_asset"],
    },
    {
        "id": "eval-008",
        "alert": {
            "id": "eval-008",
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
        },
        "expected_classification": "needs_investigation",
        "expected_severity": "medium",
        "tags": ["lateral_movement"],
    },
    {
        "id": "eval-009",
        "alert": {
            "id": "eval-009",
            "rule_name": "Suspicious web request",
            "severity": "medium",
            "category": "web",
            "hostname": "web-proxy-01",
            "source_ip": "10.1.40.18",
            "url": "http://evil-c2.example.invalid/payload.bin",
            "domain": "evil-c2.example.invalid",
            "protocol": "http",
        },
        "expected_classification": "true_positive",
        "expected_severity": "high",
        "tags": ["malicious_url"],
    },
    {
        "id": "eval-010",
        "alert": {
            "id": "eval-010",
            "rule_name": "Ambiguous authentication anomaly",
            "severity": "medium",
            "category": "authentication",
            "hostname": "workstation-mkt-04",
            "username": "a.smith",
            "source_ip": "10.1.50.44",
        },
        "expected_classification": "needs_investigation",
        "expected_severity": "medium",
        "tags": ["ambiguous"],
    },
]


def load_cases(path: str | Path | None = None) -> list[EvaluationCase]:
    if path is None:
        return [EvaluationCase.model_validate(c) for c in EVALUATION_CASES]
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [EvaluationCase.model_validate(c) for c in data]
