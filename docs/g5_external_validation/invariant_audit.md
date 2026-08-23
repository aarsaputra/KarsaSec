# Phase 12 — Architectural Invariant Audit Report

## Audit Purpose
Verify compliance with all Architectural Invariants (`INV-G5.2-01` through `INV-G5.2-08`) during the G5.2 certification run.

---

## Invariant Verification Checklist

| Invariant ID | Description | Result | Evidence |
|:---|:---|:---:|:---|
| **INV-G5.2-01** | External Corpus Authenticity & Provenance | **PASS** | OWASP and DVWA cases loaded from verified adapters. |
| **INV-G5.2-02** | Adapter Provenance & Blind Execution | **PASS** | `BlindDetectorRunner` receives ONLY `{source_code, language, framework}`. |
| **INV-G5.2-03** | No Synthetic Substitution | **PASS** | Unexecuted datasets (Juice Shop, VAmPI, WebGoat, NodeGoat) reported strictly as `NOT_EXECUTED`. Zero mock metric dictionaries. |
| **INV-G5.2-04** | Independent Ground Truth | **PASS** | Manifest ground truth isolated from detector. |
| **INV-G5.2-05** | Detector Immutability | **PASS** | Recorded SHA256 hashes in `state_freeze.md`. Zero detector edits made during evaluation. |
| **INV-G5.2-06** | Per-Dataset Metrics & Wilson CIs | **PASS** | Reported TP, TN, FP, FN, UNKNOWN, CONFLICT, EDC, and Wilson 95% CIs. |
| **INV-G5.2-07** | Failure Attribution | **PASS** | Detailed records in `failures.json` and `failure_analysis.md`. |
| **INV-G5.2-08** | No Benchmark Remediation | **PASS** | `karsasec/analysis/` remained untouched during certification. |
