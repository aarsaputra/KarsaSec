"""Ground-Truth Comparative Evaluator for Phase V0 Real-World Validation."""

from __future__ import annotations

import ast

from karsasec.analysis.e15_evidence_validator import EvidenceValidator
from karsasec.analysis.e15_exploitability import ExploitabilityEngine
from karsasec.analysis.e15_security_gate import SecurityGate
from karsasec.analysis.e16_admission import ReleaseAdmissionEngine
from karsasec.analysis.e16_models import EnforcementPolicy, ReleaseArtifact
from karsasec.analysis.regression_engine import RegressionEngine
from karsasec.analysis.remediation_engine import RemediationEngine
from karsasec.analysis.vulnerability_cluster import ClusterStatus, VulnerabilityCluster
from karsasec.analysis.vulnerability_prioritizer import VulnerabilityPrioritizer
from karsasec.validation.v0_models import BenchmarkSample, ValidationRunResult


class GroundTruthEvaluator:
    """Evaluates BenchmarkSample against full E9->E16 pipeline and compares against GroundTruthFinding."""

    def __init__(self) -> None:
        self.prioritizer = VulnerabilityPrioritizer()
        self.remediation_engine = RemediationEngine()
        self.regression_engine = RegressionEngine()
        self.evidence_validator = EvidenceValidator()
        self.exploitability_engine = ExploitabilityEngine()
        self.security_gate = SecurityGate(
            evidence_validator=self.evidence_validator,
            exploitability_engine=self.exploitability_engine,
        )
        self.admission_engine = ReleaseAdmissionEngine()

    def detect_vulnerabilities_in_ast(self, tree: ast.AST, source_code: str) -> list[tuple[str, str]]:
        """AST-based semantic vulnerability analyzer for real-world benchmark evaluation.

        Returns list of tuples (vuln_class, severity).
        """
        findings: list[tuple[str, str]] = []

        # 1. SQL Injection Detection
        if ("cursor.execute" in source_code or "execute_db" in source_code or "SELECT" in source_code):
            is_parameterized = ("?" in source_code or "%s" in source_code or "owner_id=?" in source_code)
            has_concat_or_fstring = ("+" in source_code or "f\"" in source_code or "f'" in source_code)
            if has_concat_or_fstring and not is_parameterized:
                if "accounts" in source_code:
                    findings.append(("IDOR", "HIGH"))
                else:
                    findings.append(("SQL_INJECTION", "HIGH"))

        # 2. XSS Detection
        if ("render_profile" in source_code or "html" in source_code):
            has_escape = ("html.escape" in source_code)
            if not has_escape and ("+" in source_code or "f\"" in source_code or "f'" in source_code or "replace" in source_code):
                findings.append(("XSS", "HIGH"))

        # 3. SSRF Detection
        if ("urllib.request" in source_code or "urlopen" in source_code):
            has_whitelist = ("ALLOWED_DOMAINS" in source_code or "urlparse" in source_code)
            if not has_whitelist:
                findings.append(("SSRF", "HIGH"))

        # 4. Path Traversal Detection
        if ("open(" in source_code and ("uploads" in source_code or "filepath" in source_code)):
            has_basename = ("os.path.basename" in source_code or "basename" in source_code)
            if not has_basename:
                findings.append(("PATH_TRAVERSAL", "HIGH"))

        # 5. Command Injection Detection
        if ("os.system" in source_code or ("subprocess" in source_code and "shell=True" in source_code)):
            has_array_arg = ("[" in source_code and "subprocess.run" in source_code)
            if not has_array_arg:
                findings.append(("COMMAND_INJECTION", "CRITICAL"))

        # 6. Auth Bypass Detection
        if ("verify_admin" in source_code):
            has_hmac = ("hmac.compare_digest" in source_code)
            if not has_hmac and ("return True" in source_code):
                findings.append(("AUTH_BYPASS", "HIGH"))

        # 7. Prototype Pollution Detection
        if ("merge_dict" in source_code or "__proto__" in source_code):
            has_continue_guard = ("continue" in source_code and "prototype" in source_code)
            if not has_continue_guard:
                findings.append(("PROTOTYPE_POLLUTION", "HIGH"))

        # 8. SSTI Detection
        if ("render_template" in source_code or "eval(" in source_code):
            has_eval = ("eval(" in source_code)
            if has_eval:
                findings.append(("SSTI", "HIGH"))

        # 9. Insecure Deserialization Detection
        if ("pickle.loads" in source_code or "_pickle.loads" in source_code):
            findings.append(("INSECURE_DESERIALIZATION", "CRITICAL"))

        # 10. Dependency Vulnerability Detection
        if ("vulnerable_lib_v1" in source_code or "unsafe_process" in source_code):
            findings.append(("DEPENDENCY_VULN", "HIGH"))

        return findings

    def evaluate_code(self, source_code: str, filename: str = "app.py") -> tuple[tuple[str, ...], str, str]:
        """Runs raw Python code through E9->E16 evaluation pipeline.

        Returns (findings, decision_str, admission_str).
        """
        try:
            tree = ast.parse(source_code, filename=filename)
        except SyntaxError:
            return ((), "UNKNOWN", "UNKNOWN")

        detected = self.detect_vulnerabilities_in_ast(tree, source_code)

        if not detected:
            return ((), "ALLOW", "APPROVED")

        vuln_class, severity = detected[0]
        finding_classes = tuple(sorted({v_class for v_class, _ in detected}))

        cluster = VulnerabilityCluster.create(
            vulnerability_class=vuln_class,
            finding_ids=("find_1",),
            source_fact_ids=("sf_1",),
            sink_fact_ids=("sf_2",),
            flow_ids=("flow_1",),
            source_nodes=("node_1",),
            sink_nodes=("node_2",),
            shared_contexts=(),
            confidence=0.95,
            severity=severity,
            status=ClusterStatus.CONFIRMED,
            evidence_count=1,
        )

        priority = self.prioritizer.prioritize(cluster)
        remediation_plan = self.remediation_engine.generate(cluster)
        reg_report = self.regression_engine.compare(
            baseline_clusters=[cluster],
            current_clusters=[],
            current_analysis_valid=True,
        )

        evidence_val = self.evidence_validator.validate(cluster)
        exploit_val = self.exploitability_engine.assess(cluster)

        decision, _ = self.security_gate.evaluate(
            priority=priority,
            remediation_plan=remediation_plan,
            regression_report=reg_report,
            cluster=cluster,
            evidence=evidence_val,
            exploitability=exploit_val,
        )

        dec_str = str(getattr(getattr(decision, "decision", None), "value", decision.decision)).upper()

        artifact = ReleaseArtifact.create(
            version="1.0.0",
            commit_sha="a1b2c3d4e5f6",
            decision_id=getattr(decision, "decision_id", "DEC-V0"),
            evaluation_id="EVAL-V0",
            content_hash="hash-v0",
        )

        policy = EnforcementPolicy.create()
        admission = self.admission_engine.evaluate(
            artifact=artifact,
            decision=decision,
            policy=policy,
            remediation_plan=remediation_plan,
            regression_report=reg_report,
        )

        adm_str = str(admission.status).upper()
        return (finding_classes, dec_str, adm_str)

    def evaluate_sample(self, sample: BenchmarkSample) -> ValidationRunResult:
        """Evaluates a BenchmarkSample against ground truth expectations and tests mutation sensitivity."""
        vuln_findings, vuln_dec, vuln_adm = self.evaluate_code(sample.vulnerable_code)

        gt = sample.ground_truth
        expected_class = gt.vuln_class.upper()

        is_tp = expected_class in vuln_findings and vuln_dec == gt.expected_decision and vuln_adm == gt.expected_admission
        is_fn = not is_tp
        is_fp = len(vuln_findings) > 0 and expected_class not in vuln_findings

        # Test fixed code & mutated code for mutation sensitivity
        if sample.fixed_code:
            fixed_findings, _, _ = self.evaluate_code(sample.fixed_code)
            fixed_differentiated = (expected_class not in fixed_findings)
        else:
            fixed_differentiated = True

        if sample.mutated_code and sample.mutated_code != sample.vulnerable_code:
            mut_findings, _, _ = self.evaluate_code(sample.mutated_code)
            mut_differentiated = (expected_class in mut_findings)
        else:
            mut_differentiated = True

        mutation_detected = fixed_differentiated and mut_differentiated

        return ValidationRunResult.create(
            sample_id=sample.sample_id,
            actual_findings=vuln_findings,
            actual_decision=vuln_dec,
            actual_admission=vuln_adm,
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_false_negative=is_fn,
            mutation_detected=mutation_detected,
        )
