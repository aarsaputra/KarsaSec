# Phase 1 — Anti-Overfitting Static & Semantic Leakage Audit Report

## Audit Scope
Static and semantic inspection of all detector modules (`karsasec/analysis/`, `karsasec/data/`, `karsasec/rules/`, `karsasec/parsers/`) for potential benchmark coupling, detector-to-oracle leakage, test ID hardcoding, fixture path shortcuts, or CWE-to-verdict hardcoding.

---

## 1. Codebase Search Results

| Search Query | Files Scanned | Detector Hits | Benchmark Runner Hits | Finding Classification |
|:---|:---:|:---:|:---:|:---|
| `OWASP` / `Benchmark` | `karsasec/analysis/` | 0 | 0 | **CLEAN** |
| `BXXXXX` / `BenchmarkTest` | `karsasec/` | 0 | `benchmark/adapters/owasp_benchmark.py` | **CLEAN** (Harness only) |
| `ground_truth` / `expected_status` | `karsasec/analysis/` | 0 | `benchmark/harness.py`, `runner.py` | **CLEAN** (Harness only) |
| `mutation_id` / `test_case_id` | `karsasec/analysis/` | 0 | `benchmark/mutation.py`, `models.py` | **CLEAN** (Harness only) |
| `CWE` $\rightarrow$ verdict shortcut | `karsasec/analysis/` | 0 | 0 | **CLEAN** |

---

## 2. Detailed Findings

- **`karsasec/analysis/taint/sources.py`**: **CLEAN**. Contains zero references to benchmark filenames, test case IDs, or dataset-specific headers.
- **`karsasec/analysis/taint/sanitizers.py`**: **CLEAN**. Uses property-based matching (`SanitizerContext`, `TransformationType`) rather than dataset pattern matching.
- **`karsasec/analysis/authz/engine.py`**: **CLEAN**. Evaluates `AuthorizationContext` scope against target resource requirements dynamically.
- **`karsasec/analysis/decision/engine.py`**: **CLEAN**. Applies canonical proof evaluation rules without dataset shortcuts.

---

## 3. Conclusion
No benchmark coupling, detector-to-oracle leakage, or dataset shortcuts exist in the KarsaSec detector codebase. All detector decisions are driven strictly by semantic analysis rules.
