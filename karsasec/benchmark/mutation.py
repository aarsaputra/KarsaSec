"""Security Mutation Testing Framework (Gate 5D & Phase 6 Hardening).

Supports:
- Detailed mutation status accounting (KILLED, SURVIVED, INVALID, INCONCLUSIVE)
- Root-cause tracking for surviving mutants
- Expanded mutation suite: MUT-AUTH-001 through 004, MUT-SAN-001 through 003, MUT-SRC-001 & 002, MUT-SINK-001 & 002
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from karsasec.analysis.decision.models import DecisionResolution


class MutationStatus(StrEnum):
    KILLED = "KILLED"
    SURVIVED = "SURVIVED"
    INVALID = "INVALID"
    INCONCLUSIVE = "INCONCLUSIVE"


class SecurityMutation:
    """Base class for AST/Semantic security mutations."""

    def __init__(self, mutation_id: str, description: str) -> None:
        self.mutation_id = mutation_id
        self.description = description

    def apply_mutation(self, code: str) -> str:
        raise NotImplementedError


class SinkToSafeMutation(SecurityMutation):
    """Mutates dangerous sink to safe operation (e.g. exec(cmd) -> print(cmd))."""

    def __init__(self) -> None:
        super().__init__("MUT-SINK-001", "Sink to safe operation mutation")

    def apply_mutation(self, code: str) -> str:
        return code.replace("execute(", "log_query(").replace("exec(", "print(")


class SinkThroughWrapperMutation(SecurityMutation):
    """Mutates sink by moving call through custom wrapper (MUT-SINK-002)."""

    def __init__(self) -> None:
        super().__init__("MUT-SINK-002", "Sink moved through custom wrapper")

    def apply_mutation(self, code: str) -> str:
        return code.replace("execute(", "sinkWrapper.execute(").replace("exec(", "sinkWrapper.exec(")


class SourceToConstantMutation(SecurityMutation):
    """Mutates user input source to compile-time constant (MUT-SRC-001)."""

    def __init__(self) -> None:
        super().__init__("MUT-SRC-001", "Source to constant string mutation")

    def apply_mutation(self, code: str) -> str:
        return code.replace("request.getParameter(", "'hardcoded_const' + (").replace("request.args.get(", "'hardcoded' + (")


class SourceThroughWrapperMutation(SecurityMutation):
    """Mutates source by moving call through custom request wrapper (MUT-SRC-002)."""

    def __init__(self) -> None:
        super().__init__("MUT-SRC-002", "Source moved through custom request wrapper")

    def apply_mutation(self, code: str) -> str:
        return code.replace("request.getParameter(", "customRequest.getInput(")


class SanitizationAddedMutation(SecurityMutation):
    """Adds valid sanitization routine to vulnerable code (MUT-SAN-001)."""

    def __init__(self) -> None:
        super().__init__("MUT-SAN-001", "Valid sanitization routine addition")

    def apply_mutation(self, code: str) -> str:
        return code.replace("query =", "query = PreparedStatement(")


class SanitizerRemovedMutation(SecurityMutation):
    """Removes sanitization routine from safe code (MUT-SAN-002)."""

    def __init__(self) -> None:
        super().__init__("MUT-SAN-002", "Sanitization routine removal")

    def apply_mutation(self, code: str) -> str:
        return code.replace("PreparedStatement(", "").replace("htmlspecialchars(", "")


class SanitizerIneffectiveMutation(SecurityMutation):
    """Replaces sanitizer with ineffective sanitizer (MUT-SAN-003)."""

    def __init__(self) -> None:
        super().__init__("MUT-SAN-003", "Sanitizer replaced with ineffective sanitizer")

    def apply_mutation(self, code: str) -> str:
        return code.replace("PreparedStatement(", "fake_sanitize(")


class AuthzCheckAddedMutation(SecurityMutation):
    """Adds authorization check to unauthenticated endpoint (MUT-AUTH-001)."""

    def __init__(self) -> None:
        super().__init__("MUT-AUTH-001", "Authorization check addition")

    def apply_mutation(self, code: str) -> str:
        return "@require_permission('ADMIN')\n" + code


class AuthzCheckRemovedMutation(SecurityMutation):
    """Removes authorization check from protected endpoint (MUT-AUTH-002)."""

    def __init__(self) -> None:
        super().__init__("MUT-AUTH-002", "Authorization check removal")

    def apply_mutation(self, code: str) -> str:
        return code.replace("@require_permission('ADMIN')", "").replace("check_permission()", "")


class AuthzScopeChangedMutation(SecurityMutation):
    """Changes authorization scope from ADMIN to USER (MUT-AUTH-003 / 004)."""

    def __init__(self) -> None:
        super().__init__("MUT-AUTH-004", "Authorization permission changed ADMIN -> USER")

    def apply_mutation(self, code: str) -> str:
        return code.replace("'ADMIN'", "'GUEST_READ'")


@dataclass
class MutationEvaluationResult:
    """Immutable record of security mutation evaluation outcome."""

    mutation_id: str
    original_verdict: DecisionResolution
    mutated_verdict: DecisionResolution
    syntax_valid: bool
    status: MutationStatus
    failure_reason: str = ""

    @property
    def killed(self) -> bool:
        return self.status == MutationStatus.KILLED

    def to_dict(self) -> dict[str, Any]:
        return {
            "mutation_id": self.mutation_id,
            "original_verdict": self.original_verdict.value,
            "mutated_verdict": self.mutated_verdict.value,
            "syntax_valid": self.syntax_valid,
            "status": self.status.value,
            "failure_reason": self.failure_reason,
        }


class SecurityMutationEngine:
    """Evaluates security mutations and computes overall mutation sensitivity score."""

    def evaluate_mutation(
        self,
        mutation: SecurityMutation,
        original_verdict: DecisionResolution,
        mutated_verdict: DecisionResolution,
        syntax_valid: bool = True,
    ) -> MutationEvaluationResult:
        if not syntax_valid:
            return MutationEvaluationResult(
                mutation_id=mutation.mutation_id,
                original_verdict=original_verdict,
                mutated_verdict=mutated_verdict,
                syntax_valid=False,
                status=MutationStatus.INVALID,
                failure_reason="Mutated AST failed syntax validation",
            )

        if original_verdict == DecisionResolution.UNKNOWN:
            return MutationEvaluationResult(
                mutation_id=mutation.mutation_id,
                original_verdict=original_verdict,
                mutated_verdict=mutated_verdict,
                syntax_valid=True,
                status=MutationStatus.INCONCLUSIVE,
                failure_reason="Original code was epistemically UNKNOWN prior to mutation",
            )

        if original_verdict != mutated_verdict:
            return MutationEvaluationResult(
                mutation_id=mutation.mutation_id,
                original_verdict=original_verdict,
                mutated_verdict=mutated_verdict,
                syntax_valid=True,
                status=MutationStatus.KILLED,
                failure_reason="",
            )

        # Mutated verdict equals original verdict -> Mutant SURVIVED
        return MutationEvaluationResult(
            mutation_id=mutation.mutation_id,
            original_verdict=original_verdict,
            mutated_verdict=mutated_verdict,
            syntax_valid=True,
            status=MutationStatus.SURVIVED,
            failure_reason=f"Engine verdict remained insensitive ({original_verdict.value}) after semantic mutation",
        )

    def compute_mutation_score(self, results: list[MutationEvaluationResult]) -> float:
        """Computes valid mutation score: Killed / (Killed + Survived).

        Excludes INVALID and INCONCLUSIVE mutants from denominator.
        """
        killed = sum(1 for r in results if r.status == MutationStatus.KILLED)
        survived = sum(1 for r in results if r.status == MutationStatus.SURVIVED)
        denom = killed + survived
        return (killed / denom) if denom > 0 else 0.0
