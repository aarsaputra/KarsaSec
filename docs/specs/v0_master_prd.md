# Phase V0 — Foundation Validation Master PRD

## Executive Overview
Phase V0 (**Foundation Real-World Validation**) is a mandatory, non-feature validation gate positioned immediately between the frozen E9–E16 baseline and the upcoming E17–E21 control and operations layers.

The primary objective of Phase V0 is to empirically prove that the E9–E16 analysis, decision, and admission engine is accurate, sensitive, resilient, and correct when evaluated against **real-world software codebases and real-world vulnerability patterns**, rather than solely against synthetic unit test mocks created by AI coding agents.

```text
E9–E16 Baseline (Frozen)
         │
         ▼
═══════════════════════════════════════════════════
 PHASE V0 — REAL-WORLD FOUNDATION VALIDATION GATE
═══════════════════════════════════════════════════
 ├── Real-world Vulnerability Test Corpus
 ├── Known-Vulnerable Applications & Benchmarks
 ├── True Positive / False Positive / False Negative Metrics
 ├── Semantic Mutation Testing
 ├── Differential Ground-Truth Testing
 └── Fail-Closed Resilience Verification
         │
         ├── PASS ──► Proceed to Sprint E17 (Security Control Plane)
         └── FAIL ──► Controlled Unfreeze & Upstream Repair Procedure (§4)
```

---

## 1. Problem Statement & Rationale
Synthetic unit tests created during individual feature sprints validate API contracts, state transitions, and boundary invariants. However, synthetic tests risk **self-validation bias** and **test padding** (e.g. creating tests to meet arbitrary count targets like "40 invariants"). 

Phase V0 removes test padding and self-validation bias by evaluating E9–E16 against external, real-world vulnerability benchmarks and mutated code snippets.

---

## 2. Scope & Non-Goals

### In Scope
- Constructing an immutable Real-World Test Corpus covering 11 critical vulnerability classes (SQLi, XSS, SSRF, Path Traversal, Command Injection, Auth Flaws, Authorization/IDOR, Prototype Pollution, SSTI, Insecure Deserialization, Dependency Flaws).
- Measuring detection accuracy: True Positives (TP), False Positives (FP), False Negatives (FN), Detection Coverage, Evidence Completeness, Prioritization Accuracy, Remediation Accuracy, Regression Detection, and Admission Gate Correctness.
- Semantic Mutation Testing: introducing semantic mutations (vulnerable vs safely parameterized) to verify sensitivity to security semantics rather than naive pattern matching.
- Fail-Closed resilience audit against malformed ASTs, partial CPG graphs, and edge cases.

### Non-Goals
- Adding new feature layers, new CLI flags, or external control plane capabilities (reserved for E17–E21).
- Unfreezing E9–E16 without a formal, written unfreeze proposal approved by a human reviewer.

---

## 3. Four-Layer Architecture for V0

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                         DOMAIN LAYER (V0)                                │
│ VulnerabilityCorpus, BenchmarkSample, GroundTruthFinding, ValidationMetric│
├──────────────────────────────────────────────────────────────────────────┤
│                         DECISION LAYER (V0)                              │
│ GroundTruthEvaluator, SemanticMutationEngine, DifferentialComparator      │
├──────────────────────────────────────────────────────────────────────────┤
│                         CONTROL LAYER (V0)                               │
│ ValidationGateGuard, FailureThresholdPolicy, UnfreezeTriggerPolicy        │
├──────────────────────────────────────────────────────────────────────────┤
│                       OBSERVABILITY LAYER (V0)                            │
│ AccuracyReport, MutationScorecard, RiskCoverageMatrix, LineageTrace       │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Key Performance Indicators (KPIs) & Acceptance Thresholds

| Metric | Minimum Required Threshold | Failure Consequence |
|---|---|---|
| **Critical/High Vulnerability Detection (TP Rate)** | **100%** | Critical Gate Failure $\rightarrow$ Stop E17 |
| **False Negative Rate (Critical/High)** | **0.0%** | Critical Gate Failure $\rightarrow$ Controlled Unfreeze |
| **False Positive Rate** | **< 5.0%** | Warning / Triage Required |
| **Semantic Mutation Sensitivity Score** | **100%** (100% diff detection between vuln vs fixed) | Critical Gate Failure $\rightarrow$ Rule Engine Refinement |
| **E15 Gate Correctness** | **100%** fail-closed alignment | Critical Gate Failure |
| **E16 Admission Correctness** | **100%** release protection alignment | Critical Gate Failure |

---

## 5. Exit Gate Criteria
Phase V0 is certified **PASS** if and only if:
1. Every benchmark sample in the V0 Real-World Corpus achieves the required KPI thresholds.
2. 100% of semantic mutations correctly produce findings for vulnerable variants and 0 findings for safe variants.
3. Zero unhandled exceptions occur during execution against malformed codebases.
4. Human reviewer sign-off is obtained on `docs/v0_validation_report.md`.
