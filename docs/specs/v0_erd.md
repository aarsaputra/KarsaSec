# Phase V0 — Foundation Validation Data Architecture & ERD

## Overview
This document specifies the entity-relationship model and data structures for the **Phase V0 Real-World Validation Engine**.

---

## 1. Entity-Relationship Diagram (ERD)

```text
┌───────────────────────────┐
│     ValidationCorpus      │
├───────────────────────────┤
│ PK corpus_id: String      │
│    name: String           │
│    version: String        │
│    schema_version: String │
└─────────────┬─────────────┘
              │ 1
              │
              │ N
┌─────────────▼─────────────┐          1 ┌───────────────────────────┐
│      BenchmarkSample      ├───────────►│     GroundTruthFinding    │
├───────────────────────────┤            ├───────────────────────────┤
│ PK sample_id: String      │            │ PK truth_id: String       │
│ FK corpus_id: String      │            │    vuln_class: String     │
│    category: String       │            │    expected_severity: Str │
│    vulnerable_code: String│            │    expected_decision: Str │
│    fixed_code: String     │            │    expected_admission: Str│
│    mutated_code: String   │            └───────────────────────────┘
└─────────────┬─────────────┘
              │ 1
              │
              │ N
┌─────────────▼─────────────┐
│    ValidationRunResult    │
├───────────────────────────┤
│ PK result_id: String      │
│ FK sample_id: String      │
│    actual_findings: Array │
│    actual_decision: String│
│    actual_admission: Str  │
│    is_true_positive: Bool │
│    is_false_positive: Bool│
│    is_false_negative: Bool│
│    mutation_detected: Bool│
└─────────────┬─────────────┘
              │ N
              │
              │ 1
┌─────────────▼─────────────┐
│    ValidationScorecard    │
├───────────────────────────┤
│ PK scorecard_id: String   │
│    tp_count: Int          │
│    fp_count: Int          │
│    fn_count: Int          │
│    tp_rate: Float         │
│    fp_rate: Float         │
│    mutation_score: Float  │
│    pass_gate: Boolean     │
└───────────────────────────┘
```

---

## 2. Entity Specifications

### 2.1 BenchmarkSample
- `sample_id`: SHA-256 canonical digest under namespace `V0-SAMPLE:v1:`.
- `category`: String (e.g. `"SQL_INJECTION"`, `"XSS"`, `"COMMAND_INJECTION"`).
- `vulnerable_code`: Source code string containing the vulnerable flow.
- `fixed_code`: Source code string with secure fix applied.
- `mutated_code`: Source code string with syntactic mutation.

### 2.2 GroundTruthFinding
- `truth_id`: SHA-256 canonical digest under namespace `V0-TRUTH:v1:`.
- `vuln_class`: Expected vulnerability class.
- `expected_severity`: Expected severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- `expected_decision`: Expected E15 decision (`ALLOW`, `BLOCK`, `REVIEW`, `UNKNOWN`).
- `expected_admission`: Expected E16 admission (`APPROVED`, `BLOCKED`, `REVIEW_REQUIRED`, `UNKNOWN`).

### 2.3 ValidationScorecard
- `scorecard_id`: SHA-256 canonical digest under namespace `V0-SCORECARD:v1:`.
- `tp_rate`: Calculated as $\frac{TP}{TP + FN}$.
- `fp_rate`: Calculated as $\frac{FP}{FP + TN}$.
- `mutation_score`: Percentage of mutated pairs correctly differentiated.
- `pass_gate`: Boolean flag indicating if all V0 PRD KPIs were strictly met.
