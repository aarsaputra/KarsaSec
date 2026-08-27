# Phase V0 — Foundation Validation Threat Model & Failure Modes

## Overview
This document identifies the threat vectors, evasion strategies, and failure modes that Phase V0 tests against the E9–E16 foundation engine.

---

## 1. Threat Vectors & Evasion Strategies

```text
                                  Attacker Intent
                                         │
       ┌─────────────────────────────────┼─────────────────────────────────┐
       ▼                                 ▼                                 ▼
[Code Obfuscation / AST Tampering]  [Semantic Mutation Evasion]  [Partial Evidence Injection]
       │                                 │                                 │
       ▼                                 ▼                                 ▼
(CPG Graph Disruption)             (Sanitizer Spoofing)             (Score Laundering / TOCTOU)
```

### Threat Vector 1: CPG Graph Disruption (AST / Structural Obfuscation)
- **Mechanism**: Wrapping dataflow sources or sinks in complex dynamic wrappers, nested lambdas, alias assignments, or indirect property accesses.
- **Risk**: Semantic Fact / Flow Extraction (E10/E11) fails to reconstruct full dataflow path, resulting in a **False Negative**.
- **V0 Mitigation**: Tests include aliased sources/sinks, multi-file module exports, and indirect assignment paths across all 11 vulnerability categories.

### Threat Vector 2: Fake Sanitizer Injection
- **Mechanism**: Introducing custom, ineffective wrapper functions (e.g. `def sanitize(x): return x.replace("'", "")`) that do not safely neutralize the payload.
- **Risk**: Rule Engine (E12) marks taint as sanitized, suppressing legitimate security findings.
- **V0 Mitigation**: Tests explicitly differentiate between standard validated sanitizers and custom incomplete sanitizers.

### Threat Vector 3: Semantic Mutation Blindness
- **Mechanism**: Slight variations in code syntax (e.g. string concatenation vs parameterized query placeholders) that alter security semantics.
- **Risk**: Analysis engine relies on naive string matching rather than AST dataflow semantics.
- **V0 Mitigation**: Semantic Mutation Engine generates paired code variants (vulnerable vs parameterized) for every test sample.

### Threat Vector 4: TOCTOU & Evidence Laundering
- **Mechanism**: Modifying finding/evidence metadata between evaluation stages.
- **Risk**: Invalid evidence yields an `APPROVED` release admission.
- **V0 Mitigation**: TOCTOU identity binding invariants strictly tested in Phase V0 validation runner.

---

## 2. Failure Mode Taxonomy & Impact Matrix

| Failure Mode ID | Description | Vulnerability Impact | Severity | V0 Gate Action |
|---|---|---|---|---|
| **FM-V0-01** | False Negative on Critical Sink | Un-detected Remote Code Execution / SQLi | **CRITICAL** | **STOP V0 & FAIL GATE** |
| **FM-V0-02** | Ineffective Sanitizer Accepted | Exploit Bypass in Production | **CRITICAL** | **STOP V0 & FAIL GATE** |
| **FM-V0-03** | Semantic Mutation In-sensitivity | False Negative on Refactored Code | **HIGH** | **FAIL GATE** |
| **FM-V0-04** | Upstream State Mutation | Data corruption / Non-determinism | **HIGH** | **FAIL GATE** |
| **FM-V0-05** | False Positive Rate > 5% | Developer friction / Alert fatigue | **MEDIUM** | **WARN & RE-CALIBRATE** |
| **FM-V0-06** | Unhandled Parser Exception | Analysis crash on malformed file | **MEDIUM** | **FAIL-CLOSED UNKNOWN** |

---

## 3. Threat-to-Test Traceability Matrix

```text
FM-V0-01 (Critical FN)          ──► Test Corpus Ground Truth Audit (Corpus A-K)
FM-V0-02 (Fake Sanitizer)        ──► Sanitizer Validation Matrix (Corpus S1-S5)
FM-V0-03 (Mutation Blindness)    ──► Semantic Mutation Differential Runner (Mutants M1-M22)
FM-V0-04 (Upstream Mutation)     ──► SHA-256 Baseline Re-hash Engine
FM-V0-06 (Parser Crash)          ──► Fuzzing / Malformed AST Runner
```
