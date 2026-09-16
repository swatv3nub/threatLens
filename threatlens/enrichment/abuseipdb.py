from __future__ import annotations

from typing import Any

import httpx

from threatlens.config import Settings
from threatlens.enrichment import providers
from threatlens.enrichment.base import BaseTool, ToolContext, ToolResult, ToolStatus
from threatlens.models.alerts import NormalizedAlert
from threatlens.security.allowlist import Allowlist
from threatlens.security.validation import is_private_ip, is_valid_ip

ABUSE_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBTool(BaseTool):
    name = "abuseipdb"
    reliability = 0.85

    def __init__(self, settings: Settings, allowlist: Allowlist) -> None:
        self._settings = settings
        self._allowlist = allowlist

    def is_applicable(self, alert: NormalizedAlert) -> bool:
        return bool(self._public_ips(alert))

    @staticmethod
    def _public_ips(alert: NormalizedAlert) -> list[str]:
        ips: list[str] = []
        for ip in (alert.source_ip, alert.destination_ip):
            if ip and is_valid_ip(ip) and not is_private_ip(ip):
                ips.append(ip)
        return ips

    async def execute(self, context: ToolContext) -> ToolResult:
        ips = self._public_ips(context.alert)
        if not ips:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.skipped,
                summary="no public IPs to check",
                confidence=0.0,
            )
        use_mock = self._settings.mock_enrichment or not self._settings.abuseipdb_api_key
        results: dict[str, Any] = {}
        if use_mock:
            for ip in ips:
                results[ip] = providers.mock_ip_reputation(ip, "abuseipdb").model_dump(
                    mode="json"
                )
        else:
            headers = {
                "Key": self._settings.abuseipdb_api_key or "",
                "Accept": "application/json",
            }
            async with httpx.AsyncClient(
                timeout=self._settings.tool_timeout_seconds
            ) as client:
                for ip in ips:
                    url = f"{ABUSE_BASE}/check"
                    self._allowlist.enforce(url)
                    resp = await client.get(
                        url, headers=headers, params={"ipAddress": ip, "maxAgeInDays": 90}
                    )
                    resp.raise_for_status()
                    payload = resp.json().get("data", {})
                    results[ip] = {
                        "ip": ip,
                        "malicious": payload.get("abuseConfidenceScore", 0) >= 50,
                        "confidence_score": payload.get("abuseConfidenceScore", 0),
                        "country": payload.get("countryCode"),
                        "isp": payload.get("isp"),
                        "usage_type": payload.get("usageType"),
                        "domain": payload.get("domain"),
                        "total_reports": payload.get("totalReports", 0),
                        "last_reported_at": payload.get("lastReportedAt"),
                        "source": "abuseipdb",
                    }
        flagged = sum(1 for r in results.values() if r.get("malicious"))
        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.success,
            data=results,
            summary=f"AbuseIPDB checked {len(results)} IPs, {flagged} flagged",
            confidence=self.reliability,
        )
