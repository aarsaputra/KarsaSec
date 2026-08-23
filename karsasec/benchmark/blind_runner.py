"""Multi-property Blind Detector Runner enforcing INVARIANT G5.1-01 and G5.1-02.

The detector process receives ONLY:
- source_code: str
- language: str
- framework: str

The detector DOES NOT receive:
- expected_status
- ground_truth
- CWE label derived from ground truth
- benchmark case ID
- mutation ID
- fixture name
"""

from typing import Any

from karsasec.analysis.decision.models import DecisionResolution
from karsasec.analysis.taint.sanitizers import SanitizerResolver
from karsasec.analysis.taint.sources import SourceResolver


class BlindDetectorRunner:
    """Independent multi-property blind detector runner."""

    SUPPORTED_PROPERTIES: tuple[str, ...] = (
        "SQL_INJECTION",
        "CROSS_SITE_SCRIPTING",
        "COMMAND_INJECTION",
        "SSRF",
        "PATH_TRAVERSAL",
        "AUTHORIZATION",
    )

    def __init__(self) -> None:
        self.source_resolver = SourceResolver()
        self.sanitizer_resolver = SanitizerResolver()

    def analyze_blind(self, source_code: str, language: str = "Java", framework: str = "Servlet") -> dict[str, Any]:
        """Analyzes a code snippet blindly across all security properties without ground-truth hint.

        Args:
            source_code: Source code to scan.
            language: Programming language.
            framework: Target web framework.

        Returns:
            dict containing raw predictions per security property.
        """
        source_sem = self.source_resolver.resolve_source(source_code, language=language)

        findings_by_property: dict[str, str] = {}

        if source_sem is None:
            # Unproven source -> UNKNOWN provenance for all properties
            for prop in self.SUPPORTED_PROPERTIES:
                findings_by_property[prop] = DecisionResolution.UNKNOWN.value
            return {
                "source_provenance": "UNKNOWN",
                "is_user_controlled": False,
                "findings": findings_by_property,
            }

        if not source_sem.is_user_controlled:
            # Non-HTTP object source -> SAFE across all properties
            for prop in self.SUPPORTED_PROPERTIES:
                findings_by_property[prop] = DecisionResolution.SAFE.value
            return {
                "source_provenance": source_sem.source_origin,
                "is_user_controlled": False,
                "findings": findings_by_property,
            }

        # Source is user controlled -> evaluate each security property independently
        for prop in self.SUPPORTED_PROPERTIES:
            san_sem = self.sanitizer_resolver.resolve_sanitizer(source_code, target_property=prop)
            if san_sem is not None and san_sem.is_verified_safe:
                findings_by_property[prop] = DecisionResolution.SAFE.value
            elif san_sem is not None and not san_sem.is_verified_safe:
                findings_by_property[prop] = DecisionResolution.VULNERABLE.value
            else:
                # No sanitizer found -> untyped taint reaching sink
                findings_by_property[prop] = DecisionResolution.VULNERABLE.value

        return {
            "source_provenance": source_sem.source_origin,
            "is_user_controlled": True,
            "findings": findings_by_property,
        }
