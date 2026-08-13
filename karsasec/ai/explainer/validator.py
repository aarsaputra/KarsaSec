"""Evidence-reference and verdict consistency validators for AI explanations (E13-1)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from karsasec.ai.evidence_context import SecurityFindingContext
from karsasec.ai.models import SecurityExplanation


@dataclass(frozen=True)
class ValidationResult:
    """Result of explanation validation."""

    is_valid: bool
    errors: tuple[str, ...] = field(default_factory=tuple)
    corrected_explanation: SecurityExplanation | None = None


class EvidenceReferenceValidator:
    """Validates that AI claims about sanitizers and guards are grounded in deterministic SAST evidence."""

    _SANITIZER_KEYWORDS = re.compile(
        r"\b(sanitiz(?:ed|er|ation)|escap(?:ed|ing)|clean(?:ed|ser)|htmlspecialchars|strip_tags|filter_var|addslashes|prepared statement)\b",
        re.IGNORECASE,
    )

    @classmethod
    def validate(cls, explanation: SecurityExplanation, context: SecurityFindingContext) -> ValidationResult:
        errors: list[str] = []
        has_sa_evidence = bool(context.sanitizer_evidence or context.sanitizer_constraints)

        # Check sanitizer claims if no sanitizer evidence exists
        if not has_sa_evidence:
            sa_text = explanation.sanitizer_analysis
            if cls._SANITIZER_KEYWORDS.search(sa_text) and not any(neg in sa_text.lower() for neg in ["none", "no ", "not ", "absence", "missing", "without"]):
                errors.append(
                    "AI explanation claims sanitizer protection, but deterministic SAST evidence contains NO compatible sanitizer."
                )

        # Check evidence claims
        for claim in explanation.evidence_claims:
            if claim.claim_type == "SANITIZER" and claim.is_supported and not has_sa_evidence:
                errors.append(f"AI claim '{claim.described_entity}' marked supported, but SAST evidence contains no sanitizer.")

        if errors:
            return ValidationResult(is_valid=False, errors=tuple(errors))
        return ValidationResult(is_valid=True)


class VerdictConsistencyValidator:
    """Validates that AI explanation text does not contradict the deterministic SAST SecurityVerdict."""

    _SAFE_CONTRADICTIONS = re.compile(r"\b(is safe|not vulnerable|false positive|no vulnerability|harmless|secure)\b", re.IGNORECASE)

    @classmethod
    def validate(cls, explanation: SecurityExplanation, context: SecurityFindingContext) -> ValidationResult:
        errors: list[str] = []

        if context.verdict_status in ("VULNERABLE", "NOT_PROVEN"):
            full_text = f"{explanation.summary} {explanation.why_vulnerable} {explanation.security_impact}"
            if cls._SAFE_CONTRADICTIONS.search(full_text):
                errors.append(
                    f"AI explanation claims finding is safe/false positive, contradicting deterministic SAST verdict '{context.verdict_status}'."
                )

        if errors:
            return ValidationResult(is_valid=False, errors=tuple(errors))
        return ValidationResult(is_valid=True)


class SecurityExplanationValidatorPipeline:
    """Executes full validation pipeline over raw AI explanation outputs."""

    @classmethod
    def validate_and_sanitize(
        cls,
        explanation: SecurityExplanation,
        context: SecurityFindingContext,
    ) -> tuple[bool, SecurityExplanation, list[str]]:
        all_errors: list[str] = []

        res_ev = EvidenceReferenceValidator.validate(explanation, context)
        if not res_ev.is_valid:
            all_errors.extend(res_ev.errors)

        res_v = VerdictConsistencyValidator.validate(explanation, context)
        if not res_v.is_valid:
            all_errors.extend(res_v.errors)

        if not all_errors:
            return True, explanation, []

        # Enforce fail-closed correction if ungrounded claims detected
        corrected = explanation.model_copy(deep=True)
        if not (context.sanitizer_evidence or context.sanitizer_constraints):
            corrected.sanitizer_analysis = "NONE COMPATIBLE — Deterministic analysis confirmed no compatible sanitizer on flow path."

        if context.verdict_status == "VULNERABLE":
            corrected.summary = f"Confirmed Vulnerable: {context.rule_title} ({context.cwe_id})"
            corrected.why_vulnerable = f"Taint reaches sink without proven compatibility in {context.file_path}:{context.line_number}."

        return False, corrected, all_errors
