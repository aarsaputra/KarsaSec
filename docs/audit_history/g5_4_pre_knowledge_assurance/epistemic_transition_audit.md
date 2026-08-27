# Epistemic Monotonicity Audit Report (INV-G5.4-05)

## Transition Rules
- **Module**: `karsasec/benchmark/epistemic_transition.py`
- **Test**: `tests/benchmark/test_g5_epistemic_transition.py`

---

## Forbidden Unsupported Transitions
- `UNKNOWN -> SAFE`
- `UNKNOWN -> VULNERABLE`
- `CONFLICT -> SAFE`
- `CONFLICT -> VULNERABLE`

*Requires explicit, independently validated semantic evidence to transition out of uncertainty.*
