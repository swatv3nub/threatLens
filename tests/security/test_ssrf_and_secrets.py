from __future__ import annotations

import pytest

from threatlens.security.allowlist import (
    Allowlist,
    OutboundHostNotAllowedError,
)
from threatlens.security.audit import AuditEvent, redact
from threatlens.security.secrets import SecretStr
from threatlens.security.validation import is_safe_url


def test_allowlist_blocks_arbitrary_model_url() -> None:
    allowlist = Allowlist(("www.virustotal.com",))
    with pytest.raises(OutboundHostNotAllowedError):
        allowlist.enforce("http://169.254.169.254/latest/meta-data")


def test_allowlist_rejects_subdomain_confusion() -> None:
    allowlist = Allowlist(("www.virustotal.com",))
    assert not allowlist.is_allowed("https://www.virustotal.com.evil.example/")


def test_safe_url_blocks_ssrf_targets() -> None:
    for url in (
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://169.254.169.254/",
        "file:///etc/passwd",
    ):
        safe, _ = is_safe_url(url)
        assert not safe


def test_redact_removes_secrets() -> None:
    payload = {
        "api_key": "super-secret",
        "nested": {"token": "abc", "ok": 1},
        "list": [{"password": "p"}],
    }
    cleaned = redact(payload)
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["nested"]["token"] == "[REDACTED]"
    assert cleaned["nested"]["ok"] == 1
    assert cleaned["list"][0]["password"] == "[REDACTED]"


def test_audit_event_redacts_detail() -> None:
    event = AuditEvent(
        event_type="tool_call",
        detail={"tool": "virustotal", "api_key": "leak-me"},
    )
    assert event.redacted_detail()["api_key"] == "[REDACTED]"


def test_secret_str_hides_value_in_repr() -> None:
    secret = SecretStr("top-secret")
    assert "top-secret" not in repr(secret)
    assert secret.get_secret_value() == "top-secret"
    assert bool(secret) is True
