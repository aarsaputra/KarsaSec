"""Real Mutation Execution Engine enforcing INVARIANT G5.1-04.

Executes detector against baseline original programs and mutated programs.
Evaluates whether mutations are KILLED or SURVIVED based on actual detector verdict transitions.
"""

from typing import Any

from karsasec.benchmark.blind_runner import BlindDetectorRunner


class RealMutationRunner:
    """Runner for actual detector execution against program mutations."""

    def __init__(self) -> None:
        self.detector = BlindDetectorRunner()

    def run_mutation_experiment(self, mutation_suite: list[dict[str, Any]]) -> dict[str, Any]:
        """Executes actual detector analysis across original and mutated code snippets.

        Args:
            mutation_suite: List of dicts containing:
                - 'mutation_id': str
                - 'mutation_type': str
                - 'original_code': str
                - 'mutated_code': str
                - 'target_property': str
                - 'expected_transition': str ('VULNERABLE->SAFE', 'SAFE->VULNERABLE', 'VULNERABLE->UNKNOWN')

        Returns:
            dict containing mutation execution metrics.
        """
        killed = survived = 0
        results = []

        for item in mutation_suite:
            orig_code = item["original_code"]
            mut_code = item["mutated_code"]
            target_prop = item.get("target_property", "SQL_INJECTION")
            exp_trans = item.get("expected_transition", "ANY_CHANGE")

            # 1. Actual detector execution on original code
            baseline_res = self.detector.analyze_blind(orig_code)
            baseline_verdict = baseline_res["findings"].get(target_prop, "UNKNOWN")

            # 2. Actual detector execution on mutated code
            mutated_res = self.detector.analyze_blind(mut_code)
            mutated_verdict = mutated_res["findings"].get(target_prop, "UNKNOWN")

            # 3. Independent oracle evaluation of transition
            is_killed = False
            if exp_trans == "VULNERABLE->SAFE":
                is_killed = (baseline_verdict == "VULNERABLE" and mutated_verdict == "SAFE")
            elif exp_trans == "SAFE->VULNERABLE":
                is_killed = (baseline_verdict == "SAFE" and mutated_verdict == "VULNERABLE")
            elif exp_trans == "VULNERABLE->UNKNOWN":
                is_killed = (baseline_verdict == "VULNERABLE" and mutated_verdict == "UNKNOWN")
            else:
                is_killed = (baseline_verdict != mutated_verdict)

            if is_killed:
                killed += 1
            else:
                survived += 1

            results.append({
                "mutation_id": item["mutation_id"],
                "mutation_type": item["mutation_type"],
                "baseline_verdict": baseline_verdict,
                "mutated_verdict": mutated_verdict,
                "status": "KILLED" if is_killed else "SURVIVED",
                "killed": is_killed,
            })

        total = len(mutation_suite)
        score = killed / total if total > 0 else 0.0

        return {
            "total_mutations": total,
            "killed": killed,
            "survived": survived,
            "mutation_score": score,
            "results": results,
        }
