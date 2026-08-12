# ADR E12-18: Security Decision Provenance, Finding Correlation & Evidence-Backed Verdict Engine

## Context & Problem Statement
In static analysis, raw findings often lack explicit decision provenance, rendering it difficult to trace why a finding was classified as `VULNERABLE`, `SAFE`, or `UNKNOWN`. Furthermore, multiple taint paths flowing into identical sink locations can cause duplicate findings if not properly correlated while maintaining strict isolation across distinct variable SSA versions ($x#1 vs $x#2), interprocedural call contexts, and control-flow branch polarities.

Sprint E12-18 introduces **Security Decision Provenance**, **Finding Correlation**, and an **Evidence-Backed Verdict Engine** to guarantee that every security finding emitted by KarsaSec is backed by immutable, byte-for-byte deterministic evidence.

## Architectural Authority & Principles

1. **Matrix Semantic Authority Preservation**:
   `SinkCompatibilityMatrix` (E12-13) remains the sole semantic authority for determining sink safety based on aggregated constraints (`SemanticConstraint`). `SecurityDecisionEngine` acts as an evidence assembler and provenance binder, delegating compatibility evaluations to `SinkCompatibilityMatrix`.

2. **Invariant G1 (UNKNOWN != SAFE)**:
   Incomplete evidence or unproven constraints MUST preserve `UNKNOWN` or `VULNERABLE` status. Missing evidence can NEVER silently be converted into default safety or false certainty.

3. **Invariant G2 (Matrix Proof Requirement)**:
   `SecurityDecisionEngine` MUST NOT independently declare a sink `SAFE` without explicit `COMPATIBLE` evaluation from `SinkCompatibilityMatrix` and `PROVEN` proof status.

4. **Multi-Axis Finding Correlation & Isolation**:
   `SemanticFindingCorrelator` merges equivalent findings sharing identical source, sink, rule, SSA version, call context, and branch polarity. Distinct SSA versions ($x#1 vs $x#2), distinct call contexts, or opposite branch polarities (`TRUE` vs `FALSE`) are strictly isolated and NEVER merged.

5. **Deterministic SHA-256 Fingerprinting**:
   Evidence fingerprints (`evidence_fingerprint` and `canonical_fingerprint`) are generated via canonical SHA-256 serialization over sorted reason codes, sources, provenance paths, and evidence IDs, ensuring 100% stability across `PYTHONHASHSEED=1..5`.

6. **SARIF Report Integration**:
   Security verdicts are automatically exported into SARIF output files under `result.properties.karsasec` keys (`karsasec.verdict`, `karsasec.evidence_fingerprint`, `karsasec.reason_codes`, `karsasec.provenance_path`, etc.) while maintaining full backward compatibility with legacy findings without verdicts.

## Component Architecture

- `karsasec/graph/dataflow/security_verdict.py`:
  - `VerdictStatus`: `VULNERABLE`, `SAFE`, `UNKNOWN`, `NOT_PROVEN`.
  - `DecisionReason`: Granular, machine-readable reason codes (`TAINT_REACHES_SINK`, `SANITIZER_COMPATIBLE`, `GUARD_PROVEN`, `SSA_VERSION_ISOLATED`, etc.).
  - `VerdictConfidence`: `HIGH`, `MEDIUM`, `LOW`.
  - `EvidenceReference`: Immutable link to originating evidence nodes.
  - `SecurityVerdict`: Complete verdict domain object with SHA-256 evidence fingerprinting.

- `karsasec/graph/dataflow/security_decision.py`:
  - `SecurityDecisionEngine`: Evaluates `SemanticEvidenceBundle` against `SinkCompatibilityMatrix` authority and constructs an immutable `SecurityVerdict`.

- `karsasec/graph/dataflow/finding_correlator.py`:
  - `SemanticFindingCorrelator`: Stateless correlation engine grouping equivalent verdicts into `CorrelatedFindingGroup`.

- `karsasec/core/finding/model.py`:
  - Integrated optional `verdict` field into `Finding` and `QualifiedFinding` dataclasses.

- `karsasec/core/reporting/sarif_reporter.py`:
  - Enriched SARIF output generator with custom `karsasec` verdict metadata.

- `karsasec/graph/taint_verifier.py`:
  - Primary verification entry point (`evaluate_security_verdict`) executing evidence bundle assembly, matrix evaluation, and verdict binding.

## Verification & Baseline Preservation

- **Full Pytest Suite**: 1604/1604 PASS (1559 baseline + 45 new E12-18 unit tests).
- **Adversarial Unit Test Suite**: 45/45 PASS (`tests/unit/graph/test_security_decision_e12_18.py`).
- **DVWA Baseline Qualification**: 8/8 PASS (TP=20, FN=0, Recall=100%).
- **Hash Seed Determinism**: PASS across `PYTHONHASHSEED=1..5`.
- **Ruff Code Formatting & Linting**: Clean (All checks passed).
