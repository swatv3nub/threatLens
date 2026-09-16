from __future__ import annotations

from urllib.parse import urlparse

from threatlens.config import Settings
from threatlens.security.validation import is_private_ip, is_valid_ip


class OutboundHostNotAllowedError(ValueError):
    pass


class Allowlist:
    """Restricts outbound network access to approved hosts (SSRF defense)."""

    def __init__(self, allowed_hosts: tuple[str, ...]) -> None:
        self._allowed = {h.lower() for h in allowed_hosts}

    @classmethod
    def from_settings(cls, settings: Settings) -> Allowlist:
        return cls(settings.allowed_outbound_hosts)

    def is_allowed(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        if parsed.scheme not in {"http", "https"}:
            return False
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        if is_valid_ip(host) and is_private_ip(host):
            return False
        if host in self._allowed:
            return True
        return any(host.endswith("." + allowed) for allowed in self._allowed)

    def enforce(self, url: str) -> None:
        if not self.is_allowed(url):
            raise OutboundHostNotAllowedError(
                f"outbound request blocked by allowlist: {url!r}"
            )

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return frozenset(self._allowed)
