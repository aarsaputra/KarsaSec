# K1 Independent Semantic Oracle & Blindness Report (INV-G5.4.14)

## 1. Detector Blindness Architecture
- **Detector Input**: Receives strictly `{source_code, language, framework}`.
- **Metadata Isolation**: Case ID, category, expected property, expected status, and CWE are **strictly withheld** during detector execution.
- **Verification Test**: `tests/benchmark/test_g5_k1_detector_blindness.py` passed. Mutating metadata externally does not alter detector analysis results.

---

## 2. Decoupled 2-Stage Semantic Oracle
- **Module**: `karsasec/benchmark/k1_semantic_oracle.py`
- **Stage 1 (`analyze_fixture`)**: Accepts ONLY `source_code`. Inspects AST for JWT signatures/algorithms, OAuth redirect/state/PKCE, and Business Logic authz/IDOR/state-machine patterns with ZERO knowledge of expected property/status labels.
- **Stage 2 (`compare_oracle_to_manifest`)**: Evaluates analyzer findings against manifest ground truth independently.
