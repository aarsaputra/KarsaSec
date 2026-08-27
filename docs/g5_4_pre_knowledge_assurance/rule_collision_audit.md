# Rule Collision Safety Audit Report (INV-G5.4-06)

## Analyzer Module
- **Module**: `karsasec/benchmark/rule_collision.py`
- **Test**: `tests/benchmark/test_g5_rule_collision.py`

---

## Collision Detection Categories
1. `DUPLICATE_ID`: Same rule ID present in baseline and expansion pack.
2. `DUPLICATE_SIGNATURE`: Identical `(CWE, source_pattern, sink_pattern)` tuple.
3. `PRECEDENCE_CONFLICT`: Conflicting rule precedence levels.
4. `SANITIZER_CONFLICT`: Conflicting sanitizer semantics for the same target property.
5. `VERDICT_CONFLICT`: Conflicting default verdicts.
6. `SOURCE_SINK_OVERLAP`: Overlapping regex patterns.
