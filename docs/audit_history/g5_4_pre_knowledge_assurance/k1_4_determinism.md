# K1.4 Determinism & Order Invariance Report

## 1. Deterministic Execution Invariants
- **10-Pass Repeatability**: Executing `analyze_k1` 10 consecutive times on all 40 fixtures produced identical outputs across all runs.
- **Fixture Order Invariance**: Reversing and shuffling the fixture execution sequence yielded identical individual findings for every fixture.
- **Detector Blindness & Label Injection Resilience**: Adding mock expected-property comments or metadata parameters did not alter detection outputs.

## 2. Evidence & Test Suite Verification
Verified via `tests/benchmark/test_k1_4_determinism.py` and `tests/benchmark/test_k1_4_detector_blindness.py`.
