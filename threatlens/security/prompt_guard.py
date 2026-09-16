from __future__ import annotations

import re

from pydantic import BaseModel, Field

INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
    re.compile(r"system\s*prompt", re.IGNORECASE),
    re.compile(r"call\s+(this\s+)?(external\s+)?url", re.IGNORECASE),
    re.compile(r"exfiltrate", re.IGNORECASE),
    re.compile(r"curl\s+http", re.IGNORECASE),
    re.compile(r"fetch\s+https?://", re.IGNORECASE),
    re.compile(r"new\s+instructions?:", re.IGNORECASE),
    re.compile(r"override\s+(the\s+)?(policy|rules)", re.IGNORECASE),
]

UNTRUSTED_FIELDS = (
    "command_line",
    "url",
    "domain",
    "username",
    "process_name",
    "rule_name",
)


class InjectionFinding(BaseModel):
    field: str
    pattern: str
    snippet: str


class InjectionScanResult(BaseModel):
    suspicious: bool = False
    findings: list[InjectionFinding] = Field(default_factory=list)


def scan_text(field: str, value: str) -> list[InjectionFinding]:
    findings: list[InjectionFinding] = []
    for pattern in INJECTION_PATTERNS:
        match = pattern.search(value)
        if match:
            findings.append(
                InjectionFinding(
                    field=field,
                    pattern=pattern.pattern,
                    snippet=value[max(0, match.start() - 20) : match.end() + 20],
                )
            )
    return findings


def scan_alert_fields(alert: object) -> InjectionScanResult:
    result = InjectionScanResult()
    for field in UNTRUSTED_FIELDS:
        value = getattr(alert, field, None)
        if not isinstance(value, str):
            continue
        for finding in scan_text(field, value):
            result.suspicious = True
            result.findings.append(finding)
    return result
