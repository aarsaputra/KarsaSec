"""Data models for KarsaSec HTTP Header & Log Injection Reasoning Engine (Batch C8)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class HeaderContext(StrEnum):
    LOCATION = "Location"
    SET_COOKIE = "Set-Cookie"
    CONTENT_TYPE = "Content-Type"
    CONTENT_DISPOSITION = "Content-Disposition"
    HOST = "Host"
    X_FORWARDED_HOST = "X-Forwarded-Host"
    LOG_SINK = "LOG_SINK"
    ARBITRARY_HEADER = "ARBITRARY_HEADER"
    UNKNOWN = "UNKNOWN"


class HeaderInjectionCategory(StrEnum):
    CRLF_INJECTION = "CRLF_INJECTION"
    HTTP_RESPONSE_SPLITTING = "HTTP_RESPONSE_SPLITTING"
    HTTP_HEADER_INJECTION = "HTTP_HEADER_INJECTION"
    HOST_HEADER_INJECTION = "HOST_HEADER_INJECTION"
    LOG_INJECTION = "LOG_INJECTION"
    CACHE_KEY_INJECTION = "CACHE_KEY_INJECTION"
    HEADER_VALUE_INJECTION = "HEADER_VALUE_INJECTION"
    NEWLINE_INJECTION = "NEWLINE_INJECTION"


@dataclass
class HeaderInjectionNode:
    """Represents an HTTP header or log sink evaluation node."""

    source_kind: str  # HTTP_REQUEST, HTTP_HEADER, COOKIE, PROXY_HEADER, LOG_OUTPUT, TRUSTED_CONSTANT
    source_symbol: str
    header_name: str  # Location, Set-Cookie, Host, X-Header, logger.info
    header_value: str  # Raw or transformed header value
    sink_type: str  # set_header, add_header, response.headers, redirect, logger, cookie_setter
    is_user_controlled: bool = True
    is_host_allowlisted: bool = False
    is_validated: bool = False
    canonicalized_before_validation: bool | None = None  # True, False, None (UNKNOWN)
    sanitizer_type: str | None = None  # log_sanitizer, html_sanitizer, sql_sanitizer, url_encoder, None
    framework_rejects_crlf: bool | None = None  # True, False, None (UNKNOWN)
    is_double_decoded: bool = False
    language: str = "python"


@dataclass
class HeaderInjectionEvidence:
    """Machine-readable evidence output for HTTP Header and Log Injection findings."""

    category: HeaderInjectionCategory
    source_kind: str
    source_symbol: str
    sink_type: str
    header_name: str
    header_value_control: str
    encoding_state: str
    canonicalization: bool | None
    validation: bool
    trust_boundary_crossed: bool
    impact: str
    evidence_path: list[str] = field(default_factory=list)
    resolution: str = "VULNERABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "source": {
                "kind": self.source_kind,
                "symbol": self.source_symbol,
            },
            "sink": self.sink_type,
            "header_name": self.header_name,
            "header_value_control": self.header_value_control,
            "encoding_state": self.encoding_state,
            "canonicalization": self.canonicalization,
            "validation": self.validation,
            "trust_boundary_crossed": self.trust_boundary_crossed,
            "impact": self.impact,
            "evidence_path": self.evidence_path,
            "resolution": self.resolution,
        }
