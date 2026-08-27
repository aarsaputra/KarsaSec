"""Semantic Mutation Engine for Phase V0 Real-World Security Validation."""

from __future__ import annotations

from collections.abc import Sequence

from karsasec.validation.v0_evaluator import GroundTruthEvaluator
from karsasec.validation.v0_models import BenchmarkSample


class SemanticMutationEngine:
    """Evaluates semantic sensitivity by testing paired vulnerable, fixed, and mutated code samples."""

    def __init__(self, evaluator: GroundTruthEvaluator | None = None) -> None:
        self.evaluator = evaluator or GroundTruthEvaluator()

    def evaluate_mutation_pair(self, sample: BenchmarkSample) -> dict[str, bool | float | str]:
        """Evaluates differential security semantics between vulnerable, fixed, and mutated code variants."""
        expected_class = sample.ground_truth.vuln_class.upper()

        # 1. Vulnerable variant analysis
        v_findings, v_dec, v_adm = self.evaluator.evaluate_code(sample.vulnerable_code)
        vuln_pass = (expected_class in v_findings)

        # 2. Fixed variant analysis (must NOT contain expected vulnerability class)
        if sample.fixed_code:
            f_findings, f_dec, f_adm = self.evaluator.evaluate_code(sample.fixed_code)
            fix_pass = (expected_class not in f_findings)
        else:
            fix_pass = True

        # 3. Mutated variant analysis (syntactically changed, semantically vulnerable)
        if sample.mutated_code and sample.mutated_code != sample.vulnerable_code:
            m_findings, m_dec, m_adm = self.evaluator.evaluate_code(sample.mutated_code)
            mut_pass = (expected_class in m_findings)
        else:
            mut_pass = True

        sensitivity_passed = vuln_pass and fix_pass and mut_pass

        return {
            "sample_id": sample.sample_id,
            "category": sample.category,
            "vuln_detected": vuln_pass,
            "fixed_suppressed": fix_pass,
            "mutated_detected": mut_pass,
            "sensitivity_passed": sensitivity_passed,
        }

    def evaluate_all(self, samples: Sequence[BenchmarkSample]) -> float:
        """Runs semantic mutation differential testing across all benchmark samples.

        Returns percentage score (0.0 to 100.0).
        """
        if not samples:
            return 100.0

        passed_count = 0
        for sample in samples:
            res = self.evaluate_mutation_pair(sample)
            if res["sensitivity_passed"]:
                passed_count += 1

        return (passed_count / len(samples)) * 100.0
