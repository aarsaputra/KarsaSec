# G5.1 — Blind Integrity Audit Report

## Audit Purpose
Verify complete architectural separation between detector execution and ground-truth oracle evaluation in accordance with **INVARIANT G5.1-01**, **G5.1-02**, and **G5.1-03**.

---

## 1. True Blindness Verification (`INVARIANT G5.1-01`)

- **Input Vector to Detector**:
  - `source_code`: str
  - `language`: str
  - `framework`: str
- **Excluded Metadata**:
  - `expected_status` $\rightarrow$ **HIDDEN**
  - `CWE` / `ground_truth` $\rightarrow$ **HIDDEN**
  - `vulnerability_id` $\rightarrow$ **HIDDEN**
  - `target_property` derived from ground truth $\rightarrow$ **REMOVED**

---

## 2. Multi-Property Analysis (`INVARIANT G5.1-02`)

The `BlindDetectorRunner` analyzes every input snippet across all supported security properties:
- `SQL_INJECTION`
- `CROSS_SITE_SCRIPTING`
- `COMMAND_INJECTION`
- `SSRF`
- `PATH_TRAVERSAL`
- `AUTHORIZATION`

The detector produces raw findings without knowing which CWE is being tested by the benchmark oracle.

---

## 3. Removal of Harness Heuristics (`INVARIANT G5.1-03`)

The benchmark harness contains zero pattern-matching overrides (`fake_sanitize`, `raw_v`, `unproven`, `expected_status == CONFLICT`). Verdicts are inferred purely via `karsasec/analysis/`.
