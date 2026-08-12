# E12-12 Architecture Decision Record (ADR)

**Sprint Target**: Sprint E12-12 (Pre-Dataflow Constant Propagation)  
**Date**: August 12, 2026  
**Status**: **`APPROVED FOR IMPLEMENTATION`**  

---

## 1. Executive Metric Projection

| Metric | Baseline (Post E12-11) | Conservative Projection (E12-12) | Best-Case Projection (E12-12) |
| :--- | :--- | :--- | :--- |
| **True Positives (TP)** | 20 | 20 (Mandatory Invariant) | 20 (Mandatory Invariant) |
| **False Negatives (FN)**| 0 | 0 (Mandatory Invariant) | 0 (Mandatory Invariant) |
| **Recall** | 100% | 100% | 100% |
| **False Positives (FP)**| 83 | **65 — 70** | **55 — 60** |
| **Precision** | 19.4% | **22.2% — 23.5%** | **25.0% — 26.6%** |

### Why FP ≤ 40 Cannot Be Assumed in a Single Sprint:
The remaining **83 false positives** are distributed across three distinct root cause categories:
- **Category D (Static Value Provenance / Queries)**: ~15-20 FPs. *Solvable by E12-12 Constant Propagation*.
- **Category C (Control-Flow Sanitizer Guards)**: ~30-35 FPs. *Requires subsequent Sprint E12-13 (CFG Guard Propagation)*.
- **Category F (Framework Internal Symbols & Cookie Contexts)**: ~25-30 FPs. *Requires subsequent Sprint E12-14 (Framework Context Qualifier)*.

Claiming FP ≤ 40 in E12-12 alone would violate conservative engineering principles. FP reduction MUST be measured and verified incrementally.

---

## 2. Anti-Hardcoding Audit Verification

The E12-12 Constant Propagation design has been audited against anti-hardcoding guidelines:
- **NO Rule-ID Specific Logic**: Engine relies purely on AST node types (`ast.Literal`, `ast.BinaryOp`) and scope symbol tables.
- **NO Filename / Path Specific Logic**: No checks for `dvwaPage.inc.php` or benchmark directory names.
- **NO Snippet String Matching**: No hardcoded checks for `"SHOW COLUMNS"` or specific SQL table names.
- **Pure Semantic Evaluation**: Values are classified based on AST structural composition and variable provenance.

---

## 3. Phase 10 Architecture Gate Checklist

All mandatory conditions for **`APPROVED FOR IMPLEMENTATION`** are satisfied:

- [x] **Clear Abstraction Defined**: `ConstantEvaluator` engine with 3-state Value Lattice (`CONSTANT`, `DYNAMIC`, `UNKNOWN`).
- [x] **Separated from Qualification**: Constant evaluation runs pre-dataflow in `karsasec/graph/dataflow/`, decoupled from `qualifier.py`.
- [x] **`UNKNOWN != SAFE` Invariant**: Unresolved expressions default to `UNKNOWN` and are conservatively evaluated by taint analysis.
- [x] **No Benchmark-Specific Logic**: Evaluation is 100% language-level and AST-structural.
- [x] **No Rule-ID Specific Logic**: Operates on general AST and DFG representations.
- [x] **100% Recall Invariant Protected**: Conservative fallbacks prevent false negative generation.
- [x] **Scope Limited to E12-12**: Focused exclusively on intraprocedural constant propagation.
- [x] **Test Matrix Designed**: 15 specific unit test categories defined prior to code implementation.

---

## 4. Architectural Decision Status

**FINAL GATE DECISION**: **`APPROVED FOR IMPLEMENTATION`**

Sprint E12-12 is approved to proceed to execution in the next turn. Zero production files were modified during this architecture gate task.
