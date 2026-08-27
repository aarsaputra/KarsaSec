# RISK_COVERAGE_MATRIX.md — KarsaSec Risk-Coverage Mapping

## Status: VERIFIED & AUDITED (Sprint E21 Exit Criteria §3.4)

This matrix explicitly maps critical security failure modes across E9–E21 to specific adversarial tests, ensuring zero self-validation bias.

---

## Failure Mode Mapping

| Failure Mode ID | Component Layer | Risk Description | Failure Mode Condition | Adversarial Test URI | Status |
|---|---|---|---|---|---|
| **FM-E9-01** | CPG Core | Invalid AST / Parse Failure | Syntax errors in scanned source | `tests/unit/analysis/test_cpg_core.py` | **COVERED** |
| **FM-E10-01** | Semantic Facts | Taint Laundering via Sub-calls | Missing fact propagation across contexts | `tests/unit/analysis/test_semantic_correlation.py` | **COVERED** |
| **FM-E11-01** | Semantic Flow | Flow Re-ordering | Reordered AST flow paths | `tests/unit/analysis/test_semantic_correlation.py` | **COVERED** |
| **FM-E12-01** | Rule Engine | Source-Sink Condition Bypass | Absent sanitizer validation | `tests/unit/analysis/test_rule_engine.py` | **COVERED** |
| **FM-E13-01** | Finding Correlator | Disjoint Cluster Laundering | Inconsistent evidence edge IDs | `tests/unit/analysis/test_finding_correlator.py` | **COVERED** |
| **FM-E14-01** | Priority / Remediation | Score Laundering via NaN | NaN or negative confidence inputs | `tests/unit/analysis/test_vulnerability_priority.py` | **COVERED** |
| **FM-E15-01** | Security Gate | Confirmed Vulnerability Bypass | Critical confirmed issue released | `tests/unit/analysis/test_e15_security_gate.py` | **COVERED** |
| **FM-E16-01** | Release Admission | TOCTOU Decision Mismatch | Decision ID mismatch with artifact | `tests/unit/analysis/test_e16_invariants.py` | **COVERED** |
| **FM-E16-02** | Audit Ledger | Tampered Hash Chaining | Modified audit entry hash | `tests/unit/analysis/test_e16_audit.py` | **COVERED** |
| **FM-V0-01** | Real-World Corpus | Unsanitized Vulnerability Blindness | Engine fails on real-world injection | `tests/v0_validation/test_v0_real_world_benchmarks.py` | **COVERED** |
| **FM-V0-02** | Mutation Engine | Synthetic Obfuscation Bypass | Syntactically mutated code evasion | `tests/v0_validation/test_v0_mutation_sensitivity.py` | **COVERED** |
| **FM-E17-01** | Control Plane | Null Input Bypass | None artifact or decision passed | `tests/unit/control_plane/test_e17_control_plane.py` | **COVERED** |
| **FM-E18-01** | Continuous Verif | Missing Baseline Bypass | Unregistered target verification | `tests/unit/continuous/test_e18_continuous_verification.py` | **COVERED** |
| **FM-E19-01** | Threat Intel | Wild Exploit Alert Suppression | Missing threat feed record handling | `tests/unit/threat_intel/test_e19_threat_intel.py` | **COVERED** |
| **FM-E20-01** | Autonomous Ops | Action Budget Overflow | Exceeding auto-block budget | `tests/unit/autonomous/test_e20_autonomous_ops.py` | **COVERED** |
