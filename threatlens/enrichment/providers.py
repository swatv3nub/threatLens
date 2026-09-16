from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from threatlens.models.enrichment import (
    DomainReputation,
    FileReputation,
    IPReputation,
    URLReputation,
)

KNOWN_MALICIOUS_IPS: dict[str, dict[str, Any]] = {
    "203.0.113.66": {
        "confidence_score": 100,
        "country": "RU",
        "isp": "Fictional Hosting LLC",
        "usage_type": "Data Center/Web Hosting/Transit",
        "domain": "fictional-c2.example.invalid",
        "total_reports": 214,
    },
    "198.51.100.23": {
        "confidence_score": 92,
        "country": "CN",
        "isp": "Example Telecom",
        "usage_type": "Fixed Line ISP",
        "domain": "example-telecom.invalid",
        "total_reports": 87,
    },
}

KNOWN_BENIGN_IPS: set[str] = {
    "192.0.2.50",
    "10.0.0.77",
    "8.8.8.8",
    "1.1.1.1",
}

KNOWN_MALICIOUS_HASHES: dict[str, dict[str, Any]] = {
    "44d88612fea8a8f36de82e1278abb02f" + "0" * 32: {
        "detections": 58,
        "total_engines": 72,
        "threat_labels": ["Trojan.Win32.Generic", "Backdoor.Cobalt"],
    },
}

KNOWN_MALICIOUS_DOMAINS: set[str] = {"evil-c2.example.invalid"}
KNOWN_BENIGN_DOMAINS: set[str] = {"updates.example.com", "example.com"}


def mock_ip_reputation(ip: str, source: str = "mock") -> IPReputation:
    if ip in KNOWN_MALICIOUS_IPS:
        data = KNOWN_MALICIOUS_IPS[ip]
        return IPReputation(
            ip=ip,
            malicious=True,
            known_benign=False,
            confidence_score=int(data["confidence_score"]),
            country=data["country"],
            isp=data["isp"],
            usage_type=data["usage_type"],
            domain=data["domain"],
            total_reports=int(data["total_reports"]),
            last_reported_at=datetime.now(UTC) - timedelta(hours=4),
            source=source,
            raw=data,
        )
    if ip in KNOWN_BENIGN_IPS:
        return IPReputation(
            ip=ip,
            malicious=False,
            known_benign=True,
            confidence_score=0,
            country="US",
            isp="Example Networks",
            usage_type="Content Delivery Network",
            total_reports=0,
            source=source,
        )
    return IPReputation(
        ip=ip,
        malicious=False,
        known_benign=False,
        confidence_score=5,
        country=None,
        isp=None,
        usage_type=None,
        total_reports=0,
        source=source,
    )


def mock_domain_reputation(domain: str, source: str = "mock") -> DomainReputation:
    if domain in KNOWN_MALICIOUS_DOMAINS:
        return DomainReputation(
            domain=domain,
            malicious=True,
            known_benign=False,
            reputation_score=90,
            categories=["malware", "command-and-control"],
            registrar="Fictional Registrar",
            source=source,
        )
    if domain in KNOWN_BENIGN_DOMAINS:
        return DomainReputation(
            domain=domain,
            malicious=False,
            known_benign=True,
            reputation_score=0,
            categories=["software-updates"],
            source=source,
        )
    return DomainReputation(
        domain=domain,
        malicious=False,
        known_benign=False,
        reputation_score=10,
        source=source,
    )


def mock_file_reputation(file_hash: str, source: str = "mock") -> FileReputation:
    if file_hash in KNOWN_MALICIOUS_HASHES:
        data = KNOWN_MALICIOUS_HASHES[file_hash]
        return FileReputation(
            file_hash=file_hash,
            malicious=True,
            detections=int(data["detections"]),
            total_engines=int(data["total_engines"]),
            threat_labels=list(data["threat_labels"]),
            source=source,
        )
    return FileReputation(
        file_hash=file_hash, malicious=False, detections=0, total_engines=72, source=source
    )


def mock_url_reputation(url: str, source: str = "mock") -> URLReputation:
    malicious = any(domain in url for domain in KNOWN_MALICIOUS_DOMAINS)
    return URLReputation(
        url=url,
        malicious=malicious,
        detections=41 if malicious else 0,
        total_engines=72,
        categories=["malware"] if malicious else [],
        source=source,
    )
