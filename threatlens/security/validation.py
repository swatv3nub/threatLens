from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

SUSPICIOUS_SCHEMES = {"file", "gopher", "dict", "ftp", "jar", "ldap"}


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_private_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return True
    return any(addr in net for net in PRIVATE_NETWORKS) or addr.is_reserved


def is_valid_hostname(value: str) -> bool:
    if len(value) > 253:
        return False
    return bool(HOSTNAME_RE.match(value))


def is_valid_domain(value: str) -> bool:
    if len(value) > 253:
        return False
    return bool(DOMAIN_RE.match(value))


def is_valid_hash(value: str) -> bool:
    return bool(MD5_RE.match(value) or SHA1_RE.match(value) or SHA256_RE.match(value))


def is_valid_sha256_or_md5(value: str) -> bool:
    return bool(MD5_RE.match(value) or SHA256_RE.match(value))


def is_safe_url(value: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(value)
    except ValueError:
        return False, "unparseable url"
    if parsed.scheme.lower() not in {"http", "https"}:
        return False, f"scheme not allowed: {parsed.scheme!r}"
    host = parsed.hostname
    if not host:
        return False, "missing host"
    if is_valid_ip(host) and is_private_ip(host):
        return False, "private/reserved IP target blocked (SSRF)"
    return True, "ok"


def contains_control_chars(value: str) -> bool:
    return any(ord(c) < 32 and c not in "\t\n\r" for c in value)


MAX_FIELD_LENGTH = 4096


def sanitize_text(value: str | None, *, max_length: int = MAX_FIELD_LENGTH) -> str | None:
    if value is None:
        return None
    cleaned = "".join(c for c in value if ord(c) >= 32 or c in "\t\n\r")
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + "...[truncated]"
    return cleaned
