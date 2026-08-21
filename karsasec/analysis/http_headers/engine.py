"""HTTP Header & Log Injection Reasoning Engine for Batch C8."""

from __future__ import annotations

from karsasec.analysis.http_headers.models import (
    HeaderContext,
    HeaderInjectionCategory,
    HeaderInjectionEvidence,
    HeaderInjectionNode,
)


class HTTPHeaderInjectionReasoningEngine:
    """Deterministic reasoning engine for CRLF Injection, HTTP Response Splitting, Host Header Injection, and Log Injection."""

    def evaluate_header_injection(self, node: HeaderInjectionNode) -> HeaderInjectionEvidence | None:
        """Evaluates header injection nodes, encoding transformations, sanitizers, and host allowlists."""
        # Trusted Constant Header -> SAFE
        if not node.is_user_controlled or node.source_kind == "TRUSTED_CONSTANT":
            return HeaderInjectionEvidence(
                category=HeaderInjectionCategory.HTTP_HEADER_INJECTION,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                sink_type=node.sink_type,
                header_name=node.header_name,
                header_value_control="SERVER_CONSTANT",
                encoding_state="RAW",
                canonicalization=True,
                validation=True,
                trust_boundary_crossed=False,
                impact="NONE",
                evidence_path=[node.source_kind, node.source_symbol, "constant_header"],
                resolution="SAFE",
            )

        # Framework automatically rejects CR/LF -> SAFE
        if node.framework_rejects_crlf is True:
            return HeaderInjectionEvidence(
                category=HeaderInjectionCategory.CRLF_INJECTION,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                sink_type=node.sink_type,
                header_name=node.header_name,
                header_value_control="FRAMEWORK_REJECTED",
                encoding_state="SAFE",
                canonicalization=True,
                validation=True,
                trust_boundary_crossed=False,
                impact="NONE",
                evidence_path=[node.source_kind, node.source_symbol, "framework_crlf_rejection"],
                resolution="SAFE",
            )

        # Host Allowlist -> SAFE
        if node.header_name in (HeaderContext.HOST.value, HeaderContext.X_FORWARDED_HOST.value) and node.is_host_allowlisted:
            return HeaderInjectionEvidence(
                category=HeaderInjectionCategory.HOST_HEADER_INJECTION,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                sink_type=node.sink_type,
                header_name=node.header_name,
                header_value_control="ALLOWLISTED_HOST",
                encoding_state="RAW",
                canonicalization=True,
                validation=True,
                trust_boundary_crossed=False,
                impact="NONE",
                evidence_path=[node.source_kind, node.source_symbol, "host_allowlist"],
                resolution="SAFE",
            )

        # Validated Header Value (with proper canonicalization before validation) -> SAFE
        if node.is_validated and node.canonicalized_before_validation is True:
            return HeaderInjectionEvidence(
                category=HeaderInjectionCategory.HTTP_HEADER_INJECTION,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                sink_type=node.sink_type,
                header_name=node.header_name,
                header_value_control="VALIDATED_INPUT",
                encoding_state="CANONICALIZED",
                canonicalization=True,
                validation=True,
                trust_boundary_crossed=False,
                impact="NONE",
                evidence_path=[node.source_kind, node.source_symbol, "validated_header_value"],
                resolution="SAFE",
            )

        # Validation BEFORE Canonicalization -> UNKNOWN / VULNERABLE (Bypass risk)
        if node.is_validated and node.canonicalized_before_validation is False:
            return HeaderInjectionEvidence(
                category=HeaderInjectionCategory.CRLF_INJECTION,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                sink_type=node.sink_type,
                header_name=node.header_name,
                header_value_control="FLAWED_VALIDATION_ORDER",
                encoding_state="PRE_CANONICAL_VALIDATION",
                canonicalization=False,
                validation=True,
                trust_boundary_crossed=True,
                impact="UNRESOLVED_BYPASS_RISK",
                evidence_path=[node.source_kind, node.source_symbol, "validation_before_canonicalization"],
                resolution="UNKNOWN",
            )

        # Unresolved framework behavior or unknown validation -> UNKNOWN
        if node.framework_rejects_crlf is None and node.sanitizer_type == "unknown_sanitizer":
            return HeaderInjectionEvidence(
                category=HeaderInjectionCategory.CRLF_INJECTION,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                sink_type=node.sink_type,
                header_name=node.header_name,
                header_value_control="UNKNOWN_SANITIZATION",
                encoding_state="UNRESOLVED",
                canonicalization=None,
                validation=False,
                trust_boundary_crossed=True,
                impact="UNKNOWN",
                evidence_path=[node.source_kind, node.source_symbol, "unknown_sanitizer"],
                resolution="UNKNOWN",
            )

        # Log Injection
        if node.sink_type == "logger" or node.header_name == HeaderContext.LOG_SINK.value:
            # Valid log sanitizer -> SAFE
            if node.sanitizer_type == "log_sanitizer":
                return HeaderInjectionEvidence(
                    category=HeaderInjectionCategory.LOG_INJECTION,
                    source_kind=node.source_kind,
                    source_symbol=node.source_symbol,
                    sink_type=node.sink_type,
                    header_name=node.header_name,
                    header_value_control="SANITIZED_LOG",
                    encoding_state="CLEANSED",
                    canonicalization=True,
                    validation=True,
                    trust_boundary_crossed=False,
                    impact="NONE",
                    evidence_path=[node.source_kind, node.source_symbol, "log_sanitizer"],
                    resolution="SAFE",
                )

            # Incorrect sanitizer (HTML/SQL escaping on log) -> VULNERABLE
            return HeaderInjectionEvidence(
                category=HeaderInjectionCategory.LOG_INJECTION,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                sink_type=node.sink_type,
                header_name=node.header_name,
                header_value_control="USER_CONTROLLED",
                encoding_state="UNESCAPED_LOG",
                canonicalization=False,
                validation=False,
                trust_boundary_crossed=True,
                impact="LOG_FORGERY",
                evidence_path=[node.source_kind, node.source_symbol, "logger_sink", "LOG_INJECTION"],
                resolution="VULNERABLE",
            )

        # Host Header Injection
        if node.header_name in (HeaderContext.HOST.value, HeaderContext.X_FORWARDED_HOST.value):
            return HeaderInjectionEvidence(
                category=HeaderInjectionCategory.HOST_HEADER_INJECTION,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                sink_type=node.sink_type,
                header_name=node.header_name,
                header_value_control="USER_CONTROLLED_HOST",
                encoding_state="RAW",
                canonicalization=False,
                validation=False,
                trust_boundary_crossed=True,
                impact="RESET_URL_MANIPULATION",
                evidence_path=[node.source_kind, node.source_symbol, "host_header_eval"],
                resolution="VULNERABLE",
            )

        # HTTP Response Splitting (Location / Set-Cookie / Content-Type headers + CRLF)
        if node.header_name in (HeaderContext.LOCATION.value, HeaderContext.SET_COOKIE.value, HeaderContext.CONTENT_TYPE.value):
            return HeaderInjectionEvidence(
                category=HeaderInjectionCategory.HTTP_RESPONSE_SPLITTING,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                sink_type=node.sink_type,
                header_name=node.header_name,
                header_value_control="USER_CONTROLLED",
                encoding_state="DOUBLE_DECODED_CRLF" if node.is_double_decoded else "DECODED_CRLF",
                canonicalization=False,
                validation=False,
                trust_boundary_crossed=True,
                impact="RESPONSE_SPLITTING",
                evidence_path=[node.source_kind, node.source_symbol, node.header_name, "RESPONSE_SPLITTING"],
                resolution="VULNERABLE",
            )

        # CRLF / HTTP Header Injection
        return HeaderInjectionEvidence(
            category=HeaderInjectionCategory.CRLF_INJECTION,
            source_kind=node.source_kind,
            source_symbol=node.source_symbol,
            sink_type=node.sink_type,
            header_name=node.header_name,
            header_value_control="USER_CONTROLLED",
            encoding_state="DOUBLE_DECODED_CRLF" if node.is_double_decoded else "DECODED_CRLF",
            canonicalization=False,
            validation=False,
            trust_boundary_crossed=True,
            impact="HEADER_INJECTION",
            evidence_path=[node.source_kind, node.source_symbol, "set_header", "CRLF_INJECTION"],
            resolution="VULNERABLE",
        )
