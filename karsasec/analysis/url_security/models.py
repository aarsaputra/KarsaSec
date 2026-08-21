"""Data models for KarsaSec URL Security Reasoning Engine (Batch C9 Hardened)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class URLCategory(StrEnum):
    OPEN_REDIRECT = "OPEN_REDIRECT"
    EXTERNAL_REDIRECT = "EXTERNAL_REDIRECT"
    URL_PARSER_CONFUSION = "URL_PARSER_CONFUSION"
    PARSER_DISAGREEMENT = "PARSER_DISAGREEMENT"
    SCHEME_CONFUSION = "SCHEME_CONFUSION"
    AUTHORITY_CONFUSION = "AUTHORITY_CONFUSION"
    USERINFO_CONFUSION = "USERINFO_CONFUSION"
    BACKSLASH_URL_CONFUSION = "BACKSLASH_URL_CONFUSION"
    ENCODED_URL_BYPASS = "ENCODED_URL_BYPASS"
    UNICODE_HOST_CONFUSION = "UNICODE_HOST_CONFUSION"
    IDNA_PUNYCODE_CONFUSION = "IDNA_PUNYCODE_CONFUSION"
    SCHEME_RELATIVE_REDIRECT = "SCHEME_RELATIVE_REDIRECT"
    OAUTH_REDIRECT_URI_BYPASS = "OAUTH_REDIRECT_URI_BYPASS"
    PASSWORD_RESET_URL_POISONING = "PASSWORD_RESET_URL_POISONING"
    HOST_HEADER_REDIRECT_POISONING = "HOST_HEADER_REDIRECT_POISONING"
    REDIRECT_CHAIN = "REDIRECT_CHAIN"
    SSRF_REDIRECT_CORRELATION = "SSRF_REDIRECT_CORRELATION"


@dataclass
class ParsedURL:
    """Detailed URL parser representation."""

    scheme: str
    username: str
    password: str
    hostname: str
    port: int | None
    path: str
    query: str
    fragment: str
    authority: str
    is_absolute: bool
    is_scheme_relative: bool
    normalization_steps: list[str] = field(default_factory=list)


@dataclass
class URLParserSemanticModel:
    """Multi-parser URL semantics divergence representation (C9-HARDEN-01)."""

    browser_hostname: str
    framework_hostname: str
    proxy_hostname: str
    has_parser_disagreement: bool = False


@dataclass
class RedirectHop:
    """Single redirect hop node (C9-HARDEN-02)."""

    hop_id: int
    origin: str
    target: str
    is_trusted: bool
    reason: str


@dataclass
class RedirectChainGraph:
    """Graph representation of multi-hop redirect chain (C9-HARDEN-02)."""

    hops: list[RedirectHop] = field(default_factory=list)
    initial_origin: str = ""
    final_origin: str = ""
    contains_untrusted_hop: bool = False


@dataclass
class OAuthRedirectURIPolicy:
    """OAuth exact URI canonicalization & validation policy (C9-HARDEN-03)."""

    registered_uri: str
    received_uri: str
    canonical_registered_uri: str = ""
    canonical_received_uri: str = ""
    is_exact_match: bool = False


@dataclass
class URLValidation:
    """URL validation stage metadata."""

    performed: bool
    validation_stage: str  # PRE_CANONICALIZATION, POST_CANONICALIZATION, NONE
    allowed_schemes: list[str] = field(default_factory=list)
    allowed_hosts: list[str] = field(default_factory=list)
    hostname_match: bool = False
    origin_match: bool = False
    path_match: bool = False
    canonicalized_before_validation: bool | None = None  # True, False, None (UNKNOWN)
    validation_type: str | None = None  # prefix_startswith, exact_match, relative_path, allowlist, None
    result: str = "UNKNOWN"


@dataclass
class RedirectContext:
    """Redirect execution context."""

    sink: str  # redirect, location_header, oauth_callback, reset_url_gen, ssrf_http_client
    status_code: int = 302
    location_controlled: bool = True
    external_allowed: bool = False
    redirect_chain: list[str] = field(default_factory=list)
    final_origin: str = ""


@dataclass
class URLSecurityContext:
    """Context node passed into URLSecurityReasoningEngine."""

    source_kind: str  # HTTP_REQUEST, OAUTH_PARAM, HOST_HEADER, PROXY_HEADER, TRUSTED_CONSTANT
    source_symbol: str
    raw_url: str
    sink: str = "redirect"
    is_user_controlled: bool = True
    is_host_allowlisted: bool = False
    allowed_hosts: list[str] = field(default_factory=list)
    registered_oauth_uri: str | None = None
    sanitizer_type: str | None = None  # relative_path_only, exact_match, html_escape, None
    validation_type: str | None = None  # startswith, exact, allowlist, None
    canonicalized_before_validation: bool | None = None  # True, False, None (UNKNOWN)
    framework_parser_resolved: bool | None = True  # True, False, None (UNKNOWN)
    language: str = "python"


@dataclass
class URLSecurityEvidence:
    """Machine-readable evidence output for URL Security findings."""

    category: URLCategory
    source_kind: str
    source_symbol: str
    raw_url: str
    parsed_url: dict[str, Any]
    canonical_url: str
    validation: dict[str, Any]
    trust_boundary_crossed: bool
    impact: str
    parser_semantics: dict[str, Any] | None = None
    redirect_graph: dict[str, Any] | None = None
    evidence_path: list[str] = field(default_factory=list)
    resolution: str = "VULNERABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "source": {
                "kind": self.source_kind,
                "symbol": self.source_symbol,
            },
            "raw_url": self.raw_url,
            "parsed_url": self.parsed_url,
            "canonical_url": self.canonical_url,
            "validation": self.validation,
            "trust_boundary_crossed": self.trust_boundary_crossed,
            "impact": self.impact,
            "parser_semantics": self.parser_semantics,
            "redirect_graph": self.redirect_graph,
            "evidence_path": self.evidence_path,
            "resolution": self.resolution,
        }
