# Deterministic Expansion & Order Invariance Report (INV-G5.4-07)

## Order Permutation Verification
- **Module**: `karsasec/benchmark/deterministic_expansion.py`
- **Test**: `tests/benchmark/test_g5_deterministic_expansion.py`

---

## Verification Strategy
- Runs rule loading across randomized order permutations.
- Canonicalizes findings before comparison (`canonical_findings()`).
- Confirms 100% identity across all permutations.
