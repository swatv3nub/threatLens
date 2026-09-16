from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from threatlens.enrichment.base import BaseTool, ToolContext, ToolResult, ToolStatus
from threatlens.models.alerts import NormalizedAlert
from threatlens.models.enrichment import AssetContext
from threatlens.storage.repositories import AssetRepository

DEFAULT_INVENTORY: list[dict[str, Any]] = [
    {
        "hostname": "payments-prod-01",
        "asset_type": "server",
        "environment": "production",
        "owner": "payments-team",
        "criticality": "critical",
        "department": "finance",
        "role": "payment API",
        "ip_addresses": ["10.1.20.15"],
        "operating_system": "Ubuntu 22.04",
    },
    {
        "hostname": "fileserver-02",
        "asset_type": "server",
        "environment": "production",
        "owner": "it-infra",
        "criticality": "high",
        "department": "it",
        "role": "file share",
        "ip_addresses": ["10.1.10.20"],
        "operating_system": "Windows Server 2019",
    },
    {
        "hostname": "vpn-gateway-01",
        "asset_type": "network",
        "environment": "production",
        "owner": "netops",
        "criticality": "critical",
        "department": "it",
        "role": "remote access gateway",
        "ip_addresses": ["10.1.10.5"],
        "operating_system": "pfSense",
    },
    {
        "hostname": "workstation-fin-07",
        "asset_type": "workstation",
        "environment": "corporate",
        "owner": "j.doe",
        "criticality": "medium",
        "department": "finance",
        "role": "analyst workstation",
        "ip_addresses": ["10.1.30.7"],
        "operating_system": "Windows 11",
    },
    {
        "hostname": "workstation-hr-03",
        "asset_type": "workstation",
        "environment": "corporate",
        "owner": "hr-team",
        "criticality": "low",
        "department": "hr",
        "role": "hr workstation",
        "ip_addresses": ["10.1.30.22"],
        "operating_system": "Windows 11",
    },
    {
        "hostname": "workstation-eng-11",
        "asset_type": "workstation",
        "environment": "corporate",
        "owner": "eng-team",
        "criticality": "medium",
        "department": "engineering",
        "role": "developer workstation",
        "ip_addresses": ["10.1.20.31"],
        "operating_system": "Ubuntu 24.04",
    },
    {
        "hostname": "workstation-mkt-04",
        "asset_type": "workstation",
        "environment": "corporate",
        "owner": "marketing",
        "criticality": "low",
        "department": "marketing",
        "role": "marketing workstation",
        "ip_addresses": ["10.1.50.44"],
        "operating_system": "macOS 14",
    },
    {
        "hostname": "web-proxy-01",
        "asset_type": "network",
        "environment": "production",
        "owner": "netops",
        "criticality": "high",
        "department": "it",
        "role": "web proxy",
        "ip_addresses": ["10.1.40.18"],
        "operating_system": "Debian 12",
    },
    {
        "hostname": "scan-runner-01",
        "asset_type": "server",
        "environment": "security",
        "owner": "security-team",
        "criticality": "medium",
        "department": "security",
        "role": "vulnerability scanner",
        "ip_addresses": ["192.0.2.50"],
        "operating_system": "Ubuntu 22.04",
    },
    {
        "hostname": "monitor-01",
        "asset_type": "server",
        "environment": "management",
        "owner": "it-ops",
        "criticality": "medium",
        "department": "it",
        "role": "monitoring",
        "ip_addresses": ["10.0.0.77"],
        "operating_system": "Rocky Linux 9",
    },
]


def load_inventory(path: str | Path) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("asset inventory must be a JSON list")
    return data


class AssetContextTool(BaseTool):
    name = "asset_context"
    reliability = 0.95

    def __init__(
        self,
        inventory: list[dict[str, Any]] | None = None,
        repository: AssetRepository | None = None,
    ) -> None:
        self._inventory = {a["hostname"]: a for a in (inventory or DEFAULT_INVENTORY)}
        self._repository = repository

    def _lookup(self, hostname: str) -> AssetContext | None:
        record = self._inventory.get(hostname)
        if record is None and self._repository is not None:
            row = self._repository.get(hostname)
            if row is not None:
                record = {
                    "hostname": row.hostname,
                    "asset_type": row.asset_type,
                    "environment": row.environment,
                    "owner": row.owner,
                    "criticality": row.criticality,
                    "department": row.department,
                    "role": row.role,
                    "ip_addresses": row.ip_addresses,
                    "operating_system": row.operating_system,
                }
        if record is None:
            return None
        return AssetContext(**record, found=True)

    def is_applicable(self, alert: NormalizedAlert) -> bool:
        return bool(alert.hostname)

    async def execute(self, context: ToolContext) -> ToolResult:
        hostname = context.alert.hostname
        if not hostname:
            return ToolResult(
                tool_name=self.name, status=ToolStatus.skipped, summary="no hostname"
            )
        asset = self._lookup(hostname)
        if asset is None:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.success,
                data={
                    "hostname": hostname,
                    "found": False,
                    "missing_context": "asset not present in inventory",
                },
                summary=f"no asset record for {hostname}",
                confidence=0.4,
            )
        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.success,
            data=asset.model_dump(mode="json"),
            summary=f"{hostname}: {asset.environment}/{asset.criticality} ({asset.role})",
            confidence=self.reliability,
        )
