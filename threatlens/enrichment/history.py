from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from threatlens.enrichment.base import BaseTool, ToolContext, ToolResult, ToolStatus
from threatlens.models.alerts import NormalizedAlert
from threatlens.storage.repositories import AlertRepository

HISTORY_WINDOW_HOURS = 24
CORRELATION_WINDOW_HOURS = 1


class AlertHistoryTool(BaseTool):
    name = "alert_history"
    reliability = 0.8

    def __init__(self, repository: AlertRepository | None = None) -> None:
        self._repository = repository

    def is_applicable(self, alert: NormalizedAlert) -> bool:
        return True

    async def execute(self, context: ToolContext) -> ToolResult:
        alert = context.alert
        if self._repository is None:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.success,
                data={"queries": [], "missing_context": "history repository unavailable"},
                summary="no historical repository configured",
                confidence=0.3,
            )
        queries: list[dict[str, Any]] = []
        since = datetime.now(UTC) - timedelta(hours=HISTORY_WINDOW_HOURS)
        correlation_since = datetime.now(UTC) - timedelta(
            hours=CORRELATION_WINDOW_HOURS
        )
        if alert.hostname:
            matches = self._repository.query(
                hostname=alert.hostname, since=since, exclude_id=alert.id, limit=25
            )
            queries.append(
                self._build(f"hostname={alert.hostname}", HISTORY_WINDOW_HOURS, matches)
            )
        for ip_field, ip in (
            ("source_ip", alert.source_ip),
            ("destination_ip", alert.destination_ip),
        ):
            if ip:
                matches = self._repository.query(
                    **{ip_field: ip}, since=since, exclude_id=alert.id, limit=25
                )
                queries.append(self._build(f"{ip_field}={ip}", HISTORY_WINDOW_HOURS, matches))
        if alert.file_hash:
            matches = self._repository.query(
                file_hash=alert.file_hash, since=since, exclude_id=alert.id, limit=25
            )
            queries.append(
                self._build(f"file_hash={alert.file_hash}", HISTORY_WINDOW_HOURS, matches)
            )
        if alert.username:
            matches = self._repository.query(
                username=alert.username, since=since, exclude_id=alert.id, limit=25
            )
            queries.append(
                self._build(f"username={alert.username}", HISTORY_WINDOW_HOURS, matches)
            )
        rapid = 0
        if alert.source_ip:
            rapid = len(
                self._repository.query(
                    source_ip=alert.source_ip,
                    since=correlation_since,
                    exclude_id=alert.id,
                    limit=100,
                )
            )
        total = sum(q["count"] for q in queries)
        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.success,
            data={"queries": queries, "rapid_repeat_count": rapid},
            summary=f"{total} related historical alerts; {rapid} in last hour from source",
            confidence=self.reliability,
        )

    @staticmethod
    def _build(query: str, window: int, matches: list[NormalizedAlert]) -> dict[str, Any]:
        return {
            "query": query,
            "window_hours": window,
            "count": len(matches),
            "matches": [
                {
                    "alert_id": m.id,
                    "timestamp": m.timestamp.isoformat(),
                    "rule_name": m.rule_name,
                    "severity": m.severity.value,
                }
                for m in matches[:10]
            ],
        }
