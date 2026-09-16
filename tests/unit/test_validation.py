from __future__ import annotations

import pytest

from threatlens.security.validation import (
    contains_control_chars,
    is_private_ip,
    is_safe_url,
    is_valid_domain,
    is_valid_hash,
    is_valid_hostname,
    is_valid_ip,
    sanitize_text,
)


def test_valid_ips() -> None:
    assert is_valid_ip("8.8.8.8")
    assert is_valid_ip("2001:4860:4860::8888")
    assert not is_valid_ip("999.1.1.1")
    assert not is_valid_ip("not-an-ip")


def test_private_ip_detection() -> None:
    assert is_private_ip("10.0.0.1")
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("127.0.0.1")
    assert not is_private_ip("8.8.8.8")


def test_domain_and_hostname() -> None:
    assert is_valid_domain("example.com")
    assert not is_valid_domain("not_a_domain")
    assert is_valid_hostname("payments-prod-01")
    assert is_valid_hostname("host.example.com")


def test_hash_validation() -> None:
    assert is_valid_hash("d41d8cd98f00b204e9800998ecf8427e")
    assert is_valid_hash("a" * 64)
    assert not is_valid_hash("zzzz")


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://example.com/path", True),
        ("https://example.com", True),
        ("file:///etc/passwd", False),
        ("gopher://example.com", False),
        ("http://127.0.0.1/admin", False),
        ("http://169.254.169.254/latest/meta-data", False),
        ("http://10.0.0.5/internal", False),
    ],
)
def test_ssrf_url_check(url: str, expected: bool) -> None:
    safe, _reason = is_safe_url(url)
    assert safe is expected


def test_control_chars_and_sanitize() -> None:
    assert contains_control_chars("bad\x00value")
    assert not contains_control_chars("good\nvalue")
    assert sanitize_text("a\x00b") == "ab"
    truncated = sanitize_text("x" * 100, max_length=10)
    assert truncated is not None and truncated.startswith("x" * 10)
    assert truncated.endswith("[truncated]")
