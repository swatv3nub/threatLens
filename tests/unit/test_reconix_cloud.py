from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest
from pydantic import SecretStr

from threatlens.config import Settings
from threatlens.ingestion.reconix_cloud import (
    ReconixCloudClient,
    ReconixCloudConfigurationError,
    ReconixCloudIngestor,
    ReconixCloudResponseError,
    ReconixCloudSchemaError,
    validate_result,
)
from threatlens.models.alerts import AlertSource, Severity

FIXTURES = Path(__file__).parents[1] / "fixtures" / "reconix_cloud"


def fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def settings(base_url: str = "") -> Settings:
    return Settings(
        reconix_cloud_base_url=base_url,
        reconix_cloud_api_key=SecretStr("test-key"),
        max_payload_bytes=1024 * 1024,
    )


def test_result_mapping_preserves_finding_and_maps_target_fields() -> None:
    alert = ReconixCloudIngestor(settings=settings()).parse(fixture("http.json"))

    assert alert.id == "finding_http_01"
    assert alert.source == AlertSource.reconix_cloud
    assert alert.rule_id == "finding_http_01"
    assert alert.category == "http"
    assert alert.severity == Severity.high
    assert alert.hostname == "www.example.com"
    assert alert.url == "https://www.example.com/login"
    assert alert.raw_event["evidence"]["status_code"] == 200
    assert alert.metadata["scan_id"] == "scan_http"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("info", Severity.informational),
        ("informational", Severity.informational),
        ("low", Severity.low),
        ("medium", Severity.medium),
        ("high", Severity.high),
        ("critical", Severity.critical),
    ],
)
def test_severity_mapping(value: str, expected: Severity) -> None:
    raw = fixture("minimal.json")
    raw["findings"][0]["severity"] = value
    assert ReconixCloudIngestor(settings=settings()).parse(raw).severity == expected


def test_mixed_result_creates_one_alert_per_finding() -> None:
    alerts = ReconixCloudIngestor(settings=settings()).parse_result(fixture("mixed.json"))
    assert [alert.id for alert in alerts] == [
        "finding_mixed_http",
        "finding_mixed_dns",
        "finding_mixed_port",
    ]
    assert alerts[2].destination_ip is None
    assert alerts[2].destination_port == 53
    assert alerts[2].protocol == "udp"


def test_minimal_evidence_is_valid() -> None:
    alert = ReconixCloudIngestor(settings=settings()).parse(fixture("minimal.json"))
    assert alert.raw_event["evidence"] == {}


@pytest.mark.parametrize("name", ["malformed.json", "unsupported_schema.json"])
def test_invalid_contract_is_rejected(name: str) -> None:
    with pytest.raises(ReconixCloudSchemaError):
        validate_result(fixture(name))


def test_unsupported_severity_is_rejected() -> None:
    raw = fixture("minimal.json")
    raw["findings"][0]["severity"] = "emergency"
    with pytest.raises(ReconixCloudSchemaError):
        validate_result(raw)


def test_client_requires_dedicated_credential() -> None:
    configured = settings("http://127.0.0.1:1").model_copy(update={"reconix_cloud_api_key": None})
    with pytest.raises(ReconixCloudConfigurationError):
        ReconixCloudClient(configured)


class ResultsHandler(BaseHTTPRequestHandler):
    payload: bytes = b"{}"
    requests: ClassVar[list[tuple[str, str | None]]] = []

    def do_GET(self) -> None:
        self.__class__.requests.append((self.path, self.headers.get("Authorization")))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.payload)))
        self.end_headers()
        self.wfile.write(self.payload)

    def log_message(self, *_args: object) -> None:
        return


def run_server(payload: bytes) -> tuple[ThreadingHTTPServer, threading.Thread]:
    ResultsHandler.payload = payload
    ResultsHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), ResultsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_mock_server_client_to_ingestor() -> None:
    server, thread = run_server(json.dumps(fixture("mixed.json")).encode())
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"
        ingestor = ReconixCloudIngestor(
            settings=settings(base_url),
        )
        alerts = ingestor.ingest("scan_mixed")
        assert len(alerts) == 3
        assert ResultsHandler.requests == [("/api/v1/scans/scan_mixed/results", "Bearer test-key")]
    finally:
        server.shutdown()
        thread.join()


def test_client_rejects_redirect_and_oversized_response() -> None:
    server, thread = run_server(b"x" * 1025)
    try:
        configured = settings(f"http://127.0.0.1:{server.server_port}").model_copy(
            update={"max_payload_bytes": 1024}
        )
        with pytest.raises(ReconixCloudResponseError, match="too large"):
            ReconixCloudClient(configured).get_results("scan")
    finally:
        server.shutdown()
        thread.join()
