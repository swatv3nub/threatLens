from __future__ import annotations

from typing import Any

import httpx

from threatlens.config import Settings
from threatlens.enrichment import providers
from threatlens.enrichment.base import BaseTool, ToolContext, ToolResult, ToolStatus
from threatlens.models.alerts import NormalizedAlert
from threatlens.security.allowlist import Allowlist
from threatlens.security.validation import is_safe_url

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalTool(BaseTool):
    name = "virustotal"
    reliability = 0.9

    def __init__(self, settings: Settings, allowlist: Allowlist) -> None:
        self._settings = settings
        self._allowlist = allowlist

    def is_applicable(self, alert: NormalizedAlert) -> bool:
        return bool(
            alert.source_ip
            or alert.destination_ip
            or alert.domain
            or alert.url
            or alert.file_hash
        )

    async def execute(self, context: ToolContext) -> ToolResult:
        alert = context.alert
        use_mock = self._settings.mock_enrichment or not self._settings.virustotal_api_key
        findings = self._mock_lookup(alert) if use_mock else await self._real_lookup(alert)
        if not findings:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.skipped,
                summary="no VirusTotal-matchable indicators present",
                confidence=0.0,
            )
        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.success,
            data=findings,
            summary=self._summarize(findings),
            confidence=self.reliability,
        )

    def _mock_lookup(self, alert: NormalizedAlert) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for ip in (alert.source_ip, alert.destination_ip):
            if ip:
                out[f"ip:{ip}"] = providers.mock_ip_reputation(
                    ip, "virustotal"
                ).model_dump(mode="json")
        if alert.domain:
            out[f"domain:{alert.domain}"] = providers.mock_domain_reputation(
                alert.domain, "virustotal"
            ).model_dump(mode="json")
        if alert.url:
            out[f"url:{alert.url}"] = providers.mock_url_reputation(
                alert.url, "virustotal"
            ).model_dump(mode="json")
        if alert.file_hash:
            out[f"file:{alert.file_hash}"] = providers.mock_file_reputation(
                alert.file_hash, "virustotal"
            ).model_dump(mode="json")
        return out

    async def _real_lookup(self, alert: NormalizedAlert) -> dict[str, Any]:
        headers = {"x-apikey": self._settings.virustotal_api_key or ""}
        out: dict[str, Any] = {}
        targets: list[tuple[str, str]] = []
        for ip in (alert.source_ip, alert.destination_ip):
            if ip:
                targets.append((f"/ip_addresses/{ip}", f"ip:{ip}"))
        if alert.domain:
            targets.append((f"/domains/{alert.domain}", f"domain:{alert.domain}"))
        if alert.file_hash:
            targets.append((f"/files/{alert.file_hash}", f"file:{alert.file_hash}"))
        if alert.url:
            safe, _ = is_safe_url(alert.url)
            if safe:
                import base64

                url_id = base64.urlsafe_b64encode(alert.url.encode()).decode().strip("=")
                targets.append((f"/urls/{url_id}", f"url:{alert.url}"))
        async with httpx.AsyncClient(timeout=self._settings.tool_timeout_seconds) as client:
            for path, key in targets:
                url = f"{VT_BASE}{path}"
                self._allowlist.enforce(url)
                resp = await client.get(url, headers=headers)
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                out[key] = resp.json()
        return out

    @staticmethod
    def _summarize(findings: dict[str, Any]) -> str:
        malicious = 0
        for key, value in findings.items():
            if isinstance(value, dict) and value.get("malicious") and key.split(":")[0] in {
                "ip",
                "domain",
                "url",
                "file",
            }:
                malicious += 1
        return f"VirusTotal checked {len(findings)} indicators, {malicious} flagged"
