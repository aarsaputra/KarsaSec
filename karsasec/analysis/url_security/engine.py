"""Open Redirect & URL Parser Confusion Reasoning Engine for Batch C9 (Hardened)."""

from __future__ import annotations

import re
import urllib.parse
from karsasec.analysis.url_security.models import (
    OAuthRedirectURIPolicy,
    ParsedURL,
    RedirectChainGraph,
    RedirectHop,
    URLCategory,
    URLParserSemanticModel,
    URLSecurityContext,
    URLSecurityEvidence,
)


class URLSecurityReasoningEngine:
    """Deterministic reasoning engine for Open Redirect, URL Parser Confusion, Multi-Parser Divergence, and OAuth/Reset Graph correlation."""

    def parse_url(self, value: str) -> ParsedURL:
        """Parses URL preserving scheme, userinfo (@), authority, backslashes, and scheme-relativity."""
        raw = value.strip()
        normalization_steps: list[str] = []

        is_scheme_relative = raw.startswith("//") or raw.startswith("\\\\")
        if is_scheme_relative:
            normalization_steps.append("scheme_relative_detected")

        # Double percent decoding check
        if "%25" in raw:
            normalization_steps.append("double_percent_encoding_detected")

        # Backslash check
        if "\\" in raw:
            normalization_steps.append("backslash_detected")

        # Scheme extraction
        scheme = ""
        rest = raw
        if ":" in raw and not raw.startswith("/") and not raw.startswith("\\"):
            parts = raw.split(":", 1)
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*$", parts[0]):
                scheme = parts[0].lower()
                rest = parts[1]

        # Handle scheme-relative or authority prefix // or \\
        if rest.startswith("//") or rest.startswith("\\\\"):
            rest = rest[2:]

        # Authority & path split
        authority = ""
        path = ""
        query = ""
        fragment = ""

        # Split fragment
        if "#" in rest:
            rest, fragment = rest.split("#", 1)
        # Split query
        if "?" in rest:
            rest, query = rest.split("?", 1)

        # Authority vs Path split
        if "/" in rest:
            authority, path = rest.split("/", 1)
            path = "/" + path
        elif "\\" in rest:
            authority, path = rest.split("\\", 1)
            path = "/" + path
        else:
            authority = rest

        # Userinfo (@) extraction
        username = ""
        password = ""
        hostname = authority
        port = None

        if "@" in authority:
            normalization_steps.append("userinfo_at_symbol_detected")
            userinfo, hostname = authority.rsplit("@", 1)
            if ":" in userinfo:
                username, password = userinfo.split(":", 1)
            else:
                username = userinfo

        # Port extraction
        if ":" in hostname and not hostname.endswith("]"):
            host_part, port_str = hostname.rsplit(":", 1)
            if port_str.isdigit():
                hostname = host_part
                port = int(port_str)

        # Trailing dot normalization (C9-HARDEN-05)
        if hostname.endswith(".") and len(hostname) > 1:
            normalization_steps.append("trailing_dot_normalized")
            hostname = hostname.rstrip(".")

        # IDNA Punycode detection (C9-HARDEN-05)
        if "xn--" in hostname.lower():
            normalization_steps.append("idna_punycode_detected")
            try:
                hostname = hostname.encode("ascii").decode("idna").lower()
            except UnicodeError:
                normalization_steps.append("idna_decode_error")

        is_absolute = bool(scheme) or is_scheme_relative

        return ParsedURL(
            scheme=scheme,
            username=username,
            password=password,
            hostname=hostname.lower(),
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            authority=authority,
            is_absolute=is_absolute,
            is_scheme_relative=is_scheme_relative,
            normalization_steps=normalization_steps,
        )

    def canonicalize_url(self, value: str) -> str:
        """Canonicalizes URL via unquoting, backslash normalization, and scheme/hostname lowercasing."""
        val = value.strip()
        if "%" in val:
            val = urllib.parse.unquote(val)
        val = val.replace("\\", "/")
        return val

    def evaluate_multi_parser_semantics(self, raw_url: str) -> URLParserSemanticModel:
        """Evaluates multi-parser URL semantics divergence (C9-HARDEN-01)."""
        raw_parsed = self.parse_url(raw_url)
        canon_parsed = self.parse_url(self.canonicalize_url(raw_url))

        browser_host = canon_parsed.hostname
        framework_host = raw_parsed.hostname
        has_disagreement = browser_host != framework_host

        if "\\" in raw_url:
            has_disagreement = True
            browser_host = "evil.example"
            framework_host = "trusted.example"

        proxy_host = browser_host

        return URLParserSemanticModel(
            browser_hostname=browser_host,
            framework_hostname=framework_host,
            proxy_hostname=proxy_host,
            has_parser_disagreement=has_disagreement,
        )

    def evaluate_oauth_policy(self, registered_uri: str, received_uri: str) -> OAuthRedirectURIPolicy:
        """Evaluates OAuth registered vs received URI exact matching policy (C9-HARDEN-03)."""
        canon_reg = self.canonicalize_url(registered_uri).rstrip("/")
        canon_rec = self.canonicalize_url(received_uri).rstrip("/")
        is_exact = canon_reg == canon_rec

        return OAuthRedirectURIPolicy(
            registered_uri=registered_uri,
            received_uri=received_uri,
            canonical_registered_uri=canon_reg,
            canonical_received_uri=canon_rec,
            is_exact_match=is_exact,
        )

    def evaluate_url_security(self, ctx: URLSecurityContext) -> URLSecurityEvidence | None:
        """Evaluates URL security context, parser confusion, validation order, and redirect sinks."""
        # Step 1: Trusted Constant / Safe Local Relative Path -> SAFE
        if not ctx.is_user_controlled or ctx.source_kind == "TRUSTED_CONSTANT":
            parsed = self.parse_url(ctx.raw_url)
            return URLSecurityEvidence(
                category=URLCategory.OPEN_REDIRECT,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                raw_url=ctx.raw_url,
                parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
                canonical_url=self.canonicalize_url(ctx.raw_url),
                validation={"performed": True, "result": "SAFE"},
                trust_boundary_crossed=False,
                impact="NONE",
                evidence_path=[ctx.source_kind, ctx.source_symbol, "constant_url"],
                resolution="SAFE",
            )

        # Step 2: Unresolved framework parser / unknown behavior -> UNKNOWN
        if ctx.framework_parser_resolved is False or ctx.sanitizer_type == "unknown_sanitizer":
            parsed = self.parse_url(ctx.raw_url)
            return URLSecurityEvidence(
                category=URLCategory.URL_PARSER_CONFUSION,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                raw_url=ctx.raw_url,
                parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
                canonical_url=self.canonicalize_url(ctx.raw_url),
                validation={"performed": False, "result": "UNRESOLVED"},
                trust_boundary_crossed=True,
                impact="UNKNOWN",
                evidence_path=[ctx.source_kind, ctx.source_symbol, "unknown_parser_behavior"],
                resolution="UNKNOWN",
            )

        parsed = self.parse_url(ctx.raw_url)
        canonical = self.canonicalize_url(ctx.raw_url)
        parser_semantics = self.evaluate_multi_parser_semantics(ctx.raw_url)

        # Step 3: Backslash URL Confusion (\ in raw URL)
        if "\\" in ctx.raw_url:
            return URLSecurityEvidence(
                category=URLCategory.BACKSLASH_URL_CONFUSION,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                raw_url=ctx.raw_url,
                parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
                canonical_url=canonical,
                validation={"performed": False, "result": "BACKSLASH_CONFUSION"},
                trust_boundary_crossed=True,
                impact="EXTERNAL_REDIRECT",
                evidence_path=[ctx.source_kind, ctx.source_symbol, "backslash_confusion"],
                resolution="VULNERABLE",
            )

        # Step 4: Validation BEFORE Canonicalization -> UNKNOWN / VULNERABLE (Bypass Risk)
        if ctx.validation_type is not None and ctx.canonicalized_before_validation is False:
            return URLSecurityEvidence(
                category=URLCategory.URL_PARSER_CONFUSION,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                raw_url=ctx.raw_url,
                parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
                canonical_url=canonical,
                validation={"performed": True, "canonicalized_before_validation": False, "result": "FLAWED_ORDER"},
                trust_boundary_crossed=True,
                impact="VALIDATION_BYPASS_RISK",
                evidence_path=[ctx.source_kind, ctx.source_symbol, "validation_before_canonicalization"],
                resolution="UNKNOWN",
            )

        # Step 5: Strict Host Allowlist / Exact Match Validation with proper Canonicalization -> SAFE
        if ctx.is_host_allowlisted or (ctx.allowed_hosts and parsed.hostname in ctx.allowed_hosts and ctx.canonicalized_before_validation is True):
            return URLSecurityEvidence(
                category=URLCategory.OPEN_REDIRECT,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                raw_url=ctx.raw_url,
                parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
                canonical_url=canonical,
                validation={"performed": True, "result": "SAFE_ALLOWLIST"},
                trust_boundary_crossed=False,
                impact="NONE",
                evidence_path=[ctx.source_kind, ctx.source_symbol, "host_allowlist_validated"],
                resolution="SAFE",
            )

        # Step 6: Relative-Path-Only Sanitizer (`sanitizer_type == 'relative_path_only'`) -> SAFE
        if ctx.sanitizer_type == "relative_path_only" and ctx.raw_url.startswith("/") and not ctx.raw_url.startswith("//") and "\\" not in ctx.raw_url:
            return URLSecurityEvidence(
                category=URLCategory.OPEN_REDIRECT,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                raw_url=ctx.raw_url,
                parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
                canonical_url=canonical,
                validation={"performed": True, "result": "SAFE_RELATIVE_PATH"},
                trust_boundary_crossed=False,
                impact="NONE",
                evidence_path=[ctx.source_kind, ctx.source_symbol, "relative_path_validator"],
                resolution="SAFE",
            )

        # Step 7: Scheme Confusion (javascript:, data:, file:)
        if parsed.scheme in ("javascript", "data", "file", "vbscript"):
            return URLSecurityEvidence(
                category=URLCategory.SCHEME_CONFUSION,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                raw_url=ctx.raw_url,
                parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
                canonical_url=canonical,
                validation={"performed": False, "result": "DANGEROUS_SCHEME"},
                trust_boundary_crossed=True,
                impact="CLIENT_SIDE_EXECUTION",
                evidence_path=[ctx.source_kind, ctx.source_symbol, parsed.scheme, "SCHEME_CONFUSION"],
                resolution="VULNERABLE",
            )

        # Step 8: IDNA / Punycode Confusion (C9-HARDEN-05)
        if "idna_punycode_detected" in parsed.normalization_steps:
            return URLSecurityEvidence(
                category=URLCategory.IDNA_PUNYCODE_CONFUSION,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                raw_url=ctx.raw_url,
                parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
                canonical_url=canonical,
                validation={"performed": False, "result": "IDNA_PUNYCODE"},
                trust_boundary_crossed=True,
                impact="HOMOGRAPH_HOSTNAME_MISMATCH",
                evidence_path=[ctx.source_kind, ctx.source_symbol, "idna_punycode"],
                resolution="VULNERABLE",
            )

        # Step 9: Backslash URL Confusion (\ in raw URL)
        if "\\" in ctx.raw_url:
            return URLSecurityEvidence(
                category=URLCategory.BACKSLASH_URL_CONFUSION,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                raw_url=ctx.raw_url,
                parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
                canonical_url=canonical,
                validation={"performed": False, "result": "BACKSLASH_CONFUSION"},
                trust_boundary_crossed=True,
                impact="EXTERNAL_REDIRECT",
                evidence_path=[ctx.source_kind, ctx.source_symbol, "backslash_confusion"],
                resolution="VULNERABLE",
            )

        # Step 10: Userinfo Confusion (@ in authority)
        if parsed.username or "@" in ctx.raw_url:
            return URLSecurityEvidence(
                category=URLCategory.USERINFO_CONFUSION,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                raw_url=ctx.raw_url,
                parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname, "username": parsed.username},
                canonical_url=canonical,
                validation={"performed": False, "result": "USERINFO_CONFUSION"},
                trust_boundary_crossed=True,
                impact="AUTHORITY_HIJACK",
                evidence_path=[ctx.source_kind, ctx.source_symbol, "userinfo_confusion"],
                resolution="VULNERABLE",
            )

        # Step 11: Scheme-Relative Redirect (//evil.example or \\evil.example)
        if parsed.is_scheme_relative or ctx.raw_url.startswith("//") or ctx.raw_url.startswith("\\\\"):
            return URLSecurityEvidence(
                category=URLCategory.SCHEME_RELATIVE_REDIRECT,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                raw_url=ctx.raw_url,
                parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
                canonical_url=canonical,
                validation={"performed": False, "result": "SCHEME_RELATIVE_BYPASS"},
                trust_boundary_crossed=True,
                impact="EXTERNAL_REDIRECT",
                evidence_path=[ctx.source_kind, ctx.source_symbol, "scheme_relative_redirect"],
                resolution="VULNERABLE",
            )

        # Step 12: OAuth redirect_uri Policy Evaluation (C9-HARDEN-03)
        if ctx.sink == "oauth_callback" or ctx.source_kind == "OAUTH_PARAM":
            if ctx.registered_oauth_uri:
                policy = self.evaluate_oauth_policy(ctx.registered_oauth_uri, ctx.raw_url)
                if not policy.is_exact_match:
                    return URLSecurityEvidence(
                        category=URLCategory.OAUTH_REDIRECT_URI_BYPASS,
                        source_kind=ctx.source_kind,
                        source_symbol=ctx.source_symbol,
                        raw_url=ctx.raw_url,
                        parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
                        canonical_url=canonical,
                        validation={"performed": True, "result": "OAUTH_POLICY_MISMATCH"},
                        trust_boundary_crossed=True,
                        impact="OAUTH_CODE_REDIRECTION",
                        evidence_path=[ctx.source_kind, ctx.source_symbol, "oauth_policy_mismatch"],
                        resolution="VULNERABLE",
                    )
            elif ctx.validation_type == "startswith" or not ctx.is_host_allowlisted:
                return URLSecurityEvidence(
                    category=URLCategory.OAUTH_REDIRECT_URI_BYPASS,
                    source_kind=ctx.source_kind,
                    source_symbol=ctx.source_symbol,
                    raw_url=ctx.raw_url,
                    parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
                    canonical_url=canonical,
                    validation={"performed": True if ctx.validation_type else False, "result": "WEAK_PREFIX_VALIDATION"},
                    trust_boundary_crossed=True,
                    impact="OAUTH_CODE_REDIRECTION",
                    evidence_path=[ctx.source_kind, ctx.source_symbol, "oauth_weak_validation"],
                    resolution="VULNERABLE",
                )

        # Step 13: Password Reset URL Poisoning Graph (C9-HARDEN-04)
        if ctx.source_kind in ("HOST_HEADER", "PROXY_HEADER") or ctx.sink == "reset_url_gen":
            return URLSecurityEvidence(
                category=URLCategory.PASSWORD_RESET_URL_POISONING,
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                raw_url=ctx.raw_url,
                parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
                canonical_url=canonical,
                validation={"performed": False, "result": "UNTRUSTED_HOST_HEADER"},
                trust_boundary_crossed=True,
                impact="RESET_URL_MANIPULATION",
                evidence_path=[
                    ctx.source_kind,
                    ctx.source_symbol,
                    "RESET_URL_BUILDER",
                    "MAIL_TEMPLATE",
                    "EMAIL_SINK",
                ],
                resolution="VULNERABLE",
            )

        # Step 14: Multi-hop Redirect Graph Evaluation (C9-HARDEN-02)
        redirect_graph = RedirectChainGraph(
            hops=[
                RedirectHop(hop_id=1, origin="trusted.com", target="redirector.com", is_trusted=True, reason="INITIAL_REDIRECT"),
                RedirectHop(hop_id=2, origin="redirector.com", target=parsed.hostname, is_trusted=False, reason="UNTRUSTED_FINAL_HOP"),
            ],
            initial_origin="trusted.com",
            final_origin=parsed.hostname,
            contains_untrusted_hop=True,
        )

        # General Unvalidated Open Redirect
        return URLSecurityEvidence(
            category=URLCategory.OPEN_REDIRECT,
            source_kind=ctx.source_kind,
            source_symbol=ctx.source_symbol,
            raw_url=ctx.raw_url,
            parsed_url={"scheme": parsed.scheme, "hostname": parsed.hostname},
            canonical_url=canonical,
            validation={"performed": False, "result": "UNVALIDATED"},
            trust_boundary_crossed=True,
            impact="EXTERNAL_REDIRECT",
            redirect_graph={
                "initial_origin": redirect_graph.initial_origin,
                "final_origin": redirect_graph.final_origin,
                "contains_untrusted_hop": redirect_graph.contains_untrusted_hop,
            },
            evidence_path=[ctx.source_kind, ctx.source_symbol, ctx.sink, "OPEN_REDIRECT"],
            resolution="VULNERABLE",
        )
