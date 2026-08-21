"""Data models for KarsaSec SSRF Capability & Internal Network Reasoning Engine (Batch C10)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class SSRFCategory(StrEnum):
    SSRF = "SSRF"
    BLIND_SSRF = "BLIND_SSRF"
    INTERNAL_NETWORK_ACCESS = "INTERNAL_NETWORK_ACCESS"
    CLOUD_METADATA_ACCESS = "CLOUD_METADATA_ACCESS"
    KUBERNETES_METADATA_ACCESS = "KUBERNETES_METADATA_ACCESS"
    REDIRECT_BASED_SSRF = "REDIRECT_BASED_SSRF"
    DNS_REBINDING_RISK = "DNS_REBINDING_RISK"
    URL_PARSER_CONFUSION_SSRF = "URL_PARSER_CONFUSION_SSRF"
    PROTOCOL_SMUGGLING = "PROTOCOL_SMUGGLING"
    SERVICE_DISCOVERY_ABUSE = "SERVICE_DISCOVERY_ABUSE"


class NetworkZone(StrEnum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    METADATA = "METADATA"
    KUBERNETES = "KUBERNETES"
    UNKNOWN = "UNKNOWN"


@dataclass
class TargetClassification:
    """Target hostname & IP network zone classification."""

    hostname: str
    ip_address: str | None = None
    zone: NetworkZone = NetworkZone.UNKNOWN
    is_internal: bool = False
    metadata_service: str | None = None  # AWS, GCP, Azure, DO, Alibaba, None


@dataclass
class DNSResolutionEvidence:
    """DNS resolution time-of-check time-of-use evidence (C10 Rebinding)."""

    hostname: str
    first_resolution: str
    second_resolution: str
    changes_zone: bool = False


@dataclass
class SSRFContext:
    """Context node passed into SSRFReasoningEngine."""

    source_kind: str  # HTTP_QUERY, HTTP_BODY, HTTP_HEADER, COOKIE, FILE_UPLOAD, XML_ENTITY, TEMPLATE_INPUT, REDIRECT_PARAMETER
    source_symbol: str
    target_url: str
    sink_library: str = "requests"  # requests, urllib, aiohttp, fetch, axios, HttpClient, curl, wget, socket
    sink_operation: str = "get"
    is_response_accessible: bool = True
    is_host_allowlisted: bool = False
    allowed_hosts: list[str] = field(default_factory=list)
    canonicalized_before_validation: bool | None = None  # True, False, None (UNKNOWN)
    has_parser_disagreement: bool = False
    dns_evidence: DNSResolutionEvidence | None = None
    redirect_chain: list[str] = field(default_factory=list)
    language: str = "python"


@dataclass
class SSRFEvidence:
    """Machine-readable evidence output for SSRF findings."""

    category: SSRFCategory
    source_kind: str
    source_symbol: str
    target: dict[str, Any]
    network_sink: dict[str, str]
    canonicalization: bool
    allowlist: bool
    trust_boundary_crossed: bool
    resolution: str = "VULNERABLE"
    evidence_path: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "source": {
                "kind": self.source_kind,
                "symbol": self.source_symbol,
            },
            "target": self.target,
            "network_sink": self.network_sink,
            "canonicalization": self.canonicalization,
            "allowlist": self.allowlist,
            "trust_boundary_crossed": self.trust_boundary_crossed,
            "evidence_path": self.evidence_path,
            "resolution": self.resolution,
        }
