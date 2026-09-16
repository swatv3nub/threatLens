from __future__ import annotations

import pytest

from threatlens.security.allowlist import (
    Allowlist,
    OutboundHostNotAllowedError,
)


@pytest.fixture()
def allowlist() -> Allowlist:
    return Allowlist(("www.virustotal.com", "api.abuseipdb.com"))


def test_allows_listed_host(allowlist: Allowlist) -> None:
    assert allowlist.is_allowed("https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1")


def test_blocks_unlisted_host(allowlist: Allowlist) -> None:
    assert not allowlist.is_allowed("https://evil.example.com/exfil")
    with pytest.raises(OutboundHostNotAllowedError):
        allowlist.enforce("https://evil.example.com/exfil")


def test_blocks_ssrf_targets(allowlist: Allowlist) -> None:
    assert not allowlist.is_allowed("http://127.0.0.1/")
    assert not allowlist.is_allowed("http://169.254.169.254/latest/meta-data")
    assert not allowlist.is_allowed("file:///etc/passwd")


def test_blocks_non_http_scheme(allowlist: Allowlist) -> None:
    assert not allowlist.is_allowed("gopher://www.virustotal.com/")
