from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError, field_validator

from threatlens.config import Settings, get_settings
from threatlens.ingestion.base import IngestionError, register_ingestor, safe_int
from threatlens.models.alerts import AlertSource, NormalizedAlert, Severity
from threatlens.security.validation import (
    is_safe_url,
    is_valid_domain,
    is_valid_hostname,
    is_valid_ip,
)


class ReconixCloudError(RuntimeError):
    """Base error for Reconix Cloud requests and result processing."""


class ReconixCloudConfigurationError(ReconixCloudError):
    pass


class ReconixCloudTransportError(ReconixCloudError):
    pass


class ReconixCloudResponseError(ReconixCloudError):
    pass


class ReconixCloudSchemaError(ReconixCloudError):
    pass


class ReconixFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: StrictStr = Field(min_length=1, max_length=128)
    source: StrictStr = Field(min_length=1, max_length=64)
    type: StrictStr = Field(min_length=1, max_length=128)
    title: StrictStr = Field(min_length=1, max_length=512)
    severity: StrictStr = Field(min_length=1, max_length=32)
    asset: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReconixResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: StrictStr
    scan_id: StrictStr = Field(min_length=1, max_length=128)
    target: StrictStr = Field(min_length=1, max_length=512)
    findings: list[ReconixFinding]

    @field_validator("schema_version")
    @classmethod
    def supported_version(cls, value: str) -> str:
        if value != "1.0":
            raise ValueError(f"unsupported Reconix Cloud schema version: {value!r}")
        return value


SEVERITY_MAP = {
    "info": Severity.informational,
    "informational": Severity.informational,
    "low": Severity.low,
    "medium": Severity.medium,
    "high": Severity.high,
    "critical": Severity.critical,
}


def validate_result(raw: dict[str, Any], *, max_bytes: int | None = None) -> ReconixResult:
    if not isinstance(raw, dict):
        raise ReconixCloudSchemaError("Reconix Cloud result must be a JSON object")
    try:
        serialized = json.dumps(raw, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ReconixCloudSchemaError("Reconix Cloud result contains non-JSON data") from exc
    if max_bytes is not None and len(serialized.encode()) > max_bytes:
        raise ReconixCloudSchemaError("Reconix Cloud result exceeds configured size limit")
    try:
        result = ReconixResult.model_validate(raw)
    except ValidationError as exc:
        raise ReconixCloudSchemaError("invalid Reconix Cloud result") from exc
    for finding in result.findings:
        if finding.severity.lower() not in SEVERITY_MAP:
            raise ReconixCloudSchemaError(f"unsupported finding severity: {finding.severity!r}")
    return result


class ReconixCloudClient:
    def __init__(self, settings: Settings | None = None) -> None:
        settings = settings or get_settings()
        parsed = urlparse(settings.reconix_cloud_base_url)
        key = (
            settings.reconix_cloud_api_key.get_secret_value()
            if settings.reconix_cloud_api_key
            else ""
        )
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.query
            or parsed.fragment
        ):
            raise ReconixCloudConfigurationError("RECONIX_CLOUD_BASE_URL must be an HTTP(S) origin")
        if not key.strip():
            raise ReconixCloudConfigurationError("RECONIX_CLOUD_API_KEY is required")
        self._base_url = settings.reconix_cloud_base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
        self._timeout = httpx.Timeout(
            timeout=settings.reconix_cloud_read_timeout_seconds,
            connect=settings.reconix_cloud_connect_timeout_seconds,
        )
        self._max_bytes = settings.max_payload_bytes

    def get_results(self, scan_id: str) -> dict[str, Any]:
        if not scan_id or len(scan_id) > 128 or "/" in scan_id or "\\" in scan_id:
            raise ReconixCloudResponseError("invalid scan ID")
        url = f"{self._base_url}/api/v1/scans/{scan_id}/results"
        try:
            with (
                httpx.Client(timeout=self._timeout, follow_redirects=False) as client,
                client.stream("GET", url, headers=self._headers) as response,
            ):
                if response.is_redirect:
                    raise ReconixCloudResponseError("Reconix Cloud returned a redirect")
                if response.status_code >= 400:
                    raise ReconixCloudResponseError(
                        f"Reconix Cloud returned HTTP {response.status_code}"
                    )
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > self._max_bytes:
                        raise ReconixCloudResponseError("Reconix Cloud response is too large")
        except ReconixCloudError:
            raise
        except httpx.HTTPError as exc:
            raise ReconixCloudTransportError("unable to retrieve Reconix Cloud results") from exc
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReconixCloudResponseError("Reconix Cloud returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise ReconixCloudResponseError("Reconix Cloud result must be a JSON object")
        return value


def _value(finding: ReconixFinding, *keys: str) -> Any:
    for container in (finding.asset, finding.evidence):
        for key in keys:
            if key in container and container[key] not in (None, ""):
                return container[key]
    return None


def _checked(value: Any, name: str, validator: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not validator(value):
        raise IngestionError(f"invalid Reconix Cloud {name}")
    return value


def _alert(result: ReconixResult, finding: ReconixFinding) -> NormalizedAlert:
    severity = SEVERITY_MAP[finding.severity.lower()]
    hostname = _checked(_value(finding, "hostname", "host"), "hostname", is_valid_hostname)
    domain_value = _value(finding, "domain")
    if domain_value is None and finding.type.lower() == "dns":
        domain_value = _value(finding, "name")
    domain = _checked(domain_value, "domain", is_valid_domain)
    url_value = _value(finding, "url")
    if url_value is not None and (not isinstance(url_value, str) or not is_safe_url(url_value)[0]):
        raise IngestionError("invalid Reconix Cloud URL")
    source_ip = _checked(_value(finding, "source_ip", "src_ip"), "source IP", is_valid_ip)
    destination_ip = _checked(
        _value(finding, "destination_ip", "dest_ip", "dst_ip", "ip"),
        "destination IP",
        is_valid_ip,
    )
    port_value = _value(finding, "destination_port", "dest_port", "dst_port", "port")
    port = safe_int(port_value)
    if port_value is not None and (port is None or not 0 <= port <= 65535):
        raise IngestionError("invalid Reconix Cloud port")
    metadata = dict(finding.metadata)
    metadata.update(
        {
            "scan_id": result.scan_id,
            "finding_id": finding.finding_id,
            "schema_version": result.schema_version,
            "reconix_source": finding.source,
        }
    )
    if result.target:
        metadata["scan_target"] = result.target
    return NormalizedAlert(
        id=finding.finding_id,
        source=AlertSource.reconix_cloud,
        rule_id=finding.finding_id,
        rule_name=finding.title,
        severity=severity,
        category=finding.type,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=port,
        protocol=_value(finding, "protocol", "proto"),
        hostname=hostname,
        domain=domain,
        url=url_value,
        raw_event=finding.model_dump(),
        metadata=metadata,
    )


class ReconixCloudIngestor:
    source = AlertSource.reconix_cloud

    def __init__(
        self, client: ReconixCloudClient | None = None, settings: Settings | None = None
    ) -> None:
        self.client = client
        self.settings = settings or get_settings()

    def parse_result(self, raw: dict[str, Any]) -> list[NormalizedAlert]:
        result = validate_result(raw, max_bytes=self.settings.max_payload_bytes)
        return [_alert(result, finding) for finding in result.findings]

    def parse(self, raw: dict[str, Any]) -> NormalizedAlert:
        alerts = self.parse_result(raw)
        if len(alerts) != 1:
            raise IngestionError("Reconix Cloud parse requires exactly one finding")
        return alerts[0]

    def ingest(self, scan_id: str) -> list[NormalizedAlert]:
        client = self.client or ReconixCloudClient(self.settings)
        raw = client.get_results(scan_id)
        result = validate_result(raw, max_bytes=self.settings.max_payload_bytes)
        if result.scan_id != scan_id:
            raise ReconixCloudSchemaError("Reconix Cloud result scan_id does not match request")
        return [_alert(result, finding) for finding in result.findings]


register_ingestor(ReconixCloudIngestor())
