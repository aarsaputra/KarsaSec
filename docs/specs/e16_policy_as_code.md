# Sprint E16 — Policy-as-Code Engine Specification

## Overview
The Policy-as-Code Engine (`karsasec/analysis/e16_policy.py`) evaluates security decisions against explicit release policy parameters.

## Precedence Hierarchy
1. **Rule 01 — Missing/None Input**: Returns `UNKNOWN`.
2. **Rule 02 — TOCTOU Identity Binding**: Validates `artifact.decision_id == decision.decision_id`. Mismatch returns `UNKNOWN`.
3. **Rule 03 — Score Laundering Protection**: Rejects `NaN`, `Inf`, `< 0`, or `> 1.0` scores $\rightarrow$ `UNKNOWN`.
4. **Rule 04 — Evidence & Exploitability Validity**: `evidence_valid` or `exploitability_valid` False $\rightarrow$ `UNKNOWN`.
5. **Rule 05 — E15 UNKNOWN Decision**: Returns `UNKNOWN`.
6. **Rule 06 — E15 BLOCK Decision**: Returns `BLOCKED`.
7. **Rule 07 — Regression State**: Regression `FAIL` $\rightarrow$ `BLOCKED`; `UNKNOWN` $\rightarrow$ `UNKNOWN`.
8. **Rule 08 — Remediation Plan**: Plan `BLOCKED` $\rightarrow$ `BLOCKED`; `UNKNOWN` $\rightarrow$ `UNKNOWN`.
9. **Rule 09 — Explicit E15 REVIEW**: Returns `REVIEW_REQUIRED`.
10. **Rule 10 — Policy Threshold**: Confidence $< minimum\_confidence$ $\rightarrow$ `BLOCKED`.
11. **Rule 11 — Explicit ALLOW**: Returns `APPROVED` only when ALL prior rules pass.

> **CRITICAL INVARIANT**: `UNKNOWN ≠ REVIEW_REQUIRED ≠ BLOCKED ≠ APPROVED`.
