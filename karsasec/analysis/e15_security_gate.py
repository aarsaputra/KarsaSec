"""Sprint E15 — Security Gate Controller.

Orchestrates evidence validation, exploitability assessment, regression gate checks,
and policy evaluation to produce immutable SecurityDecision and SecurityGateResult records.
"""

from typing import Any

from karsasec.analysis.e15_evidence_validator import EvidenceValidator
from karsasec.analysis.e15_exploitability import ExploitabilityEngine
from karsasec.analysis.e15_models import (
    DecisionStatus,
    EvidenceValidation,
    ExploitabilityAssessment,
    SecurityDecision,
    SecurityGateResult,
    SecurityPolicy,
)
from karsasec.analysis.e15_security_policy import SecurityPolicyEngine


class SecurityGate:
    """Automated Security Release Gate & Decision Orchestrator."""

    def __init__(
        self,
        evidence_validator: EvidenceValidator | None = None,
        exploitability_engine: ExploitabilityEngine | None = None,
        policy_engine: SecurityPolicyEngine | None = None,
    ) -> None:
        self.evidence_validator = evidence_validator or EvidenceValidator()
        self.exploitability_engine = exploitability_engine or ExploitabilityEngine()
        self.policy_engine = policy_engine or SecurityPolicyEngine()

    def evaluate(
        self,
        priority: Any = None,
        remediation_plan: Any = None,
        regression_report: Any = None,
        cluster: Any = None,
        evidence: EvidenceValidation | None = None,
        exploitability: ExploitabilityAssessment | None = None,
        policy: SecurityPolicy | None = None,
    ) -> tuple[SecurityDecision, SecurityGateResult]:
        """Evaluates the 10-step fail-closed security decision hierarchy."""
        evaluated_rules: list[str] = []
        failed_rules: list[str] = []

        active_policy = policy or self.policy_engine.default_policy

        # Rule 1 — Invalid Policy
        evaluated_rules.append("Rule_01_Valid_Policy")
        if active_policy is None or not active_policy.is_valid():
            failed_rules.append("Rule_01_Valid_Policy")
            return self._build_unknown(
                priority, remediation_plan, regression_report, active_policy,
                evaluated_rules, failed_rules, "Invalid or missing security policy"
            )

        # Rule 2 — Invalid Evidence
        active_evidence = evidence or self.evidence_validator.validate(cluster)
        evaluated_rules.append("Rule_02_Valid_Evidence")
        if not active_evidence.evidence_valid:
            failed_rules.append("Rule_02_Valid_Evidence")
            return self._build_unknown(
                priority, remediation_plan, regression_report, active_policy,
                evaluated_rules, failed_rules, f"Invalid evidence: {active_evidence.validation_reason}"
            )

        # Rule 3 — Invalid Exploitability
        active_exploitability = exploitability or self.exploitability_engine.assess(cluster)
        evaluated_rules.append("Rule_03_Valid_Exploitability")
        if not active_exploitability.assessment_valid:
            failed_rules.append("Rule_03_Valid_Exploitability")
            return self._build_unknown(
                priority, remediation_plan, regression_report, active_policy,
                evaluated_rules, failed_rules, f"Invalid exploitability: {active_exploitability.rationale}"
            )

        # Rule 4 — UNKNOWN Upstream State & Invalid Status String Validation (VULN-005 fix)
        evaluated_rules.append("Rule_04_Upstream_State_Known")
        raw_p_status = getattr(priority, "priority_status", getattr(priority, "status", "UNKNOWN"))
        p_status = str(getattr(raw_p_status, "value", raw_p_status)).upper()
        raw_r_status = getattr(remediation_plan, "status", "UNKNOWN")
        r_status = str(getattr(raw_r_status, "value", raw_r_status)).upper() if remediation_plan else "UNKNOWN"
        raw_reg_status = getattr(regression_report, "status", "NOT_TESTED")
        reg_status = str(getattr(raw_reg_status, "value", raw_reg_status)).upper() if regression_report else "NOT_TESTED"
        raw_reg_change = getattr(regression_report, "change", "UNKNOWN")
        reg_change = str(getattr(raw_reg_change, "value", raw_reg_change)).upper() if regression_report else "UNKNOWN"

        KNOWN_PRIORITY_STATUSES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "BLOCKED", "UNKNOWN", "NONE"}
        KNOWN_REMEDIATION_STATUSES = {"REQUIRED", "RECOMMENDED", "OPTIONAL", "NONE", "BLOCKED", "UNKNOWN"}

        if p_status not in KNOWN_PRIORITY_STATUSES or r_status not in KNOWN_REMEDIATION_STATUSES:
            failed_rules.append("Rule_04_Upstream_State_Known")
            return self._build_unknown(
                priority, remediation_plan, regression_report, active_policy,
                evaluated_rules, failed_rules, f"Unrecognized upstream status injection detected: priority='{p_status}', remediation='{r_status}'"
            )

        if p_status == "UNKNOWN" or r_status == "UNKNOWN" or reg_status == "UNKNOWN":
            failed_rules.append("Rule_04_Upstream_State_Known")
            return self._build_unknown(
                priority, remediation_plan, regression_report, active_policy,
                evaluated_rules, failed_rules, "Upstream priority, remediation, or regression status is UNKNOWN"
            )

        # Rule 5 — Security Regression
        evaluated_rules.append("Rule_05_No_Security_Regression")
        if reg_change in ("FAIL", "PERSISTENT", "CHANGED"):
            failed_rules.append("Rule_05_No_Security_Regression")
            return self._build_decision(
                priority, remediation_plan, regression_report, active_policy,
                DecisionStatus.BLOCK, evaluated_rules, failed_rules,
                f"Security regression detected: status {reg_status}, change {reg_change}"
            )

        # Rule 9 — BLOCKED Upstream
        evaluated_rules.append("Rule_09_Upstream_Not_Blocked")
        c_status = str(getattr(cluster, "status", "")).upper()
        if p_status == "BLOCKED" or r_status == "BLOCKED" or c_status == "BLOCKED":
            failed_rules.append("Rule_09_Upstream_Not_Blocked")
            return self._build_decision(
                priority, remediation_plan, regression_report, active_policy,
                DecisionStatus.BLOCK, evaluated_rules, failed_rules,
                "Upstream vulnerability cluster or remediation status is BLOCKED"
            )

        # Rule 6 — Confirmed Critical
        evaluated_rules.append("Rule_06_Confirmed_Critical_Guard")
        if p_status == "CRITICAL" and r_status == "REQUIRED":
            # Policy determines BLOCK vs REVIEW, NEVER ALLOW by default
            decision_crit = DecisionStatus.BLOCK if active_policy.block_unknown else DecisionStatus.REVIEW
            failed_rules.append("Rule_06_Confirmed_Critical_Guard")
            return self._build_decision(
                priority, remediation_plan, regression_report, active_policy,
                decision_crit, evaluated_rules, failed_rules,
                "Confirmed CRITICAL vulnerability requires remediation"
            )

        # Rule 7 — Confirmed High
        evaluated_rules.append("Rule_07_Confirmed_High_Guard")
        if p_status == "HIGH" and r_status == "REQUIRED":
            failed_rules.append("Rule_07_Confirmed_High_Guard")
            return self._build_decision(
                priority, remediation_plan, regression_report, active_policy,
                DecisionStatus.REVIEW, evaluated_rules, failed_rules,
                "Confirmed HIGH vulnerability requires review"
            )

        # Rule 8 — Candidate (RECOMMENDED)
        evaluated_rules.append("Rule_08_Candidate_Remediation")
        if r_status == "RECOMMENDED":
            return self._build_decision(
                priority, remediation_plan, regression_report, active_policy,
                DecisionStatus.REVIEW, evaluated_rules, failed_rules,
                "Vulnerability remediation is RECOMMENDED"
            )

        # Rule 10 — Safe Terminal State (ALLOW)
        evaluated_rules.append("Rule_10_Safe_Terminal_State")
        p_score = getattr(priority, "score", 0.0) if priority else 0.0
        p_conf = getattr(priority, "confidence", 1.0) if priority else 1.0

        if p_conf < active_policy.minimum_confidence:
            failed_rules.append("Rule_10_Safe_Terminal_State")
            return self._build_decision(
                priority, remediation_plan, regression_report, active_policy,
                DecisionStatus.REVIEW, evaluated_rules, failed_rules,
                f"Confidence {p_conf} below minimum policy threshold {active_policy.minimum_confidence}"
            )

        return self._build_decision(
            priority, remediation_plan, regression_report, active_policy,
            DecisionStatus.ALLOW, evaluated_rules, failed_rules,
            "All security policy predicates satisfied"
        )

    def _build_unknown(
        self,
        priority: Any,
        remediation_plan: Any,
        regression_report: Any,
        policy: SecurityPolicy,
        evaluated_rules: list[str],
        failed_rules: list[str],
        reason: str,
    ) -> tuple[SecurityDecision, SecurityGateResult]:
        return self._build_decision(
            priority, remediation_plan, regression_report, policy,
            DecisionStatus.UNKNOWN, evaluated_rules, failed_rules, reason
        )

    def _build_decision(
        self,
        priority: Any,
        remediation_plan: Any,
        regression_report: Any,
        policy: SecurityPolicy,
        status: DecisionStatus,
        evaluated_rules: list[str],
        failed_rules: list[str],
        reason: str,
    ) -> tuple[SecurityDecision, SecurityGateResult]:
        p_id = getattr(priority, "priority_id", "UNKNOWN-PRIORITY") if priority else "UNKNOWN-PRIORITY"
        plan_id = getattr(remediation_plan, "plan_id", "UNKNOWN-PLAN") if remediation_plan else "UNKNOWN-PLAN"
        fp_id = getattr(regression_report, "fingerprint_id", "UNKNOWN-FINGERPRINT") if regression_report else "UNKNOWN-FINGERPRINT"
        reg_status = str(getattr(regression_report, "status", "UNKNOWN")) if regression_report else "UNKNOWN"
        conf = float(getattr(priority, "confidence", 1.0)) if priority else 1.0

        decision_id = SecurityDecision.compute_decision_id(
            priority_id=p_id,
            remediation_plan_id=plan_id,
            fingerprint_id=fp_id,
            decision=status,
            evidence_valid=True if status != DecisionStatus.UNKNOWN else False,
            exploitability_valid=True if status != DecisionStatus.UNKNOWN else False,
            regression_status=reg_status,
            policy_version=policy.policy_version if policy else "1.0.0",
        )

        decision = SecurityDecision(
            decision_id=decision_id,
            priority_id=p_id,
            remediation_plan_id=plan_id,
            fingerprint_id=fp_id,
            decision=status,
            confidence=conf,
            rationale=reason,
            policy_version=policy.policy_version if policy else "1.0.0",
            evidence_valid=True if status != DecisionStatus.UNKNOWN else False,
            exploitability_valid=True if status != DecisionStatus.UNKNOWN else False,
            regression_status=reg_status,
        )

        p_id_str = policy.policy_id if policy else "POL-UNKNOWN"
        gate_id = SecurityGateResult.compute_gate_id(
            decision_id=decision_id,
            policy_id=p_id_str,
            evaluated_rules=evaluated_rules,
            failed_rules=failed_rules,
        )

        gate_result = SecurityGateResult(
            gate_id=gate_id,
            decision_id=decision_id,
            passed=(status == DecisionStatus.ALLOW),
            blocked=(status == DecisionStatus.BLOCK),
            requires_review=(status == DecisionStatus.REVIEW),
            unknown=(status == DecisionStatus.UNKNOWN),
            failed_rules=tuple(sorted(failed_rules)),
            evaluated_rules=tuple(sorted(evaluated_rules)),
            policy_version=policy.policy_version if policy else "1.0.0",
        )

        return decision, gate_result
