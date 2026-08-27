# Phase 12 — Architectural Invariant Audit Report (G5.3)

## Audit Purpose
Verify compliance with all 8 G5.3 Architectural Non-Negotiable Invariants (`INV-G5.3-01` through `INV-G5.3-08`) during the certification run.

---

## Invariant Verification Checklist

| Invariant ID | Description | Result | Evidence |
|:---|:---|:---:|:---|
| **INV-G5.3-01** | Real Corpus Only | **PASS** | OWASP and DVWA loaded from real adapters. Unexecuted datasets marked `NOT_EXECUTED`. Zero synthetic metrics. |
| **INV-G5.3-02** | Provenance Traceable | **PASS** | `CanonicalCase` maintains complete provenance schema (`dataset`, `version`, `source_artifact`, `line_range`, `sha256`). |
| **INV-G5.3-03** | Detector Blindness | **PASS** | `BlindDetectorRunner` receives ONLY `{source_code, language, framework}`. Verified in `test_g5_blind_boundary.py`. |
| **INV-G5.3-04** | Detector Immutability | **PASS** | Hashes recorded in `state_freeze.md`. Zero edits made to `karsasec/analysis/` during evaluation. |
| **INV-G5.3-05** | No Benchmark Tuning | **PASS** | `karsasec/analysis/` remained untouched. Failures classified into taxonomy in `failures.json`. |
| **INV-G5.3-06** | Epistemic Safety | **PASS** | `UNKNOWN != SAFE`, `UNKNOWN != VULNERABLE`, `CONFLICT != SAFE`, `CONFLICT != VULNERABLE`. |
| **INV-G5.3-07** | Dynamic Metrics & Wilson CIs | **PASS** | Calculated Strict Precision, Recall, FPR, FNR, Specificity, EDC, and exact 95% Wilson CIs. |
| **INV-G5.3-08** | Dataset Status Taxonomy | **PASS** | Datasets categorized into `EXECUTED` and `NOT_EXECUTED`. |
