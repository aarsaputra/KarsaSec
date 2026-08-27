# Phase V0 — Foundation Validation Execution Contract

## Status: BINDING IMPLEMENTATION CONTRACT

This contract specifies the exact implementation boundary, file layout, class interfaces, and verification protocol for **Phase V0 Foundation Real-World Validation**.

---

## 1. File & Directory Layout

Phase V0 validation code MUST be developed strictly within the following dedicated namespace:

```text
karsasec/
└── validation/
    ├── __init__.py
    ├── v0_models.py           # Immutable corpus, benchmark, and scorecard dataclasses
    ├── v0_corpus_loader.py    # Immutable JSON benchmark loader
    ├── v0_evaluator.py        # Ground-truth comparative runner
    ├── v0_mutation_engine.py  # Semantic mutation sensitivity engine
    └── v0_scorecard.py        # KPI & gate calculation engine

tests/
└── v0_validation/
    ├── test_v0_corpus_integrity.py
    ├── test_v0_real_world_benchmarks.py
    ├── test_v0_mutation_sensitivity.py
    └── test_v0_gate_pass_fail.py

docs/
├── v0_master_prd.md
├── v0_threat_model.md
├── v0_test_corpus_spec.md
├── v0_erd.md
├── v0_execution_contract.md
└── v0_validation_report.md  # Generated after V0 execution
```

---

## 2. Global Invariants & Strict Constraints

1. **Zero Upstream Mutation**: No file under `karsasec/cpg/`, `karsasec/query/`, `karsasec/framework/`, or `karsasec/analysis/` may be edited, patched, or modified during V0 execution. Verified by SHA-256 snapshot comparison across all 84 baseline files.
2. **Deterministic Evaluation**: Execution against the V0 corpus MUST yield identical scorecards regardless of `PYTHONHASHSEED` (verified under `0` and `42`).
3. **Fail-Closed Gate**: If any Critical/High True Positive is missed ($FN > 0$) or E15/E16 gate alignment fails, V0 returns `GATE_FAIL` and halts progress to Sprint E17.
4. **No Code Generation Inventions**: AI agents MUST execute this contract exactly as written.

---

## 3. Class Contracts & Method Signatures

### `v0_models.py`
```python
@dataclass(frozen=True)
class BenchmarkSample:
    sample_id: str
    category: str
    vulnerable_code: str
    fixed_code: str
    mutated_code: str
    ground_truth: GroundTruthFinding

@dataclass(frozen=True)
class ValidationScorecard:
    scorecard_id: str
    total_samples: int
    true_positives: int
    false_positives: int
    false_negatives: int
    tp_rate: float
    fp_rate: float
    mutation_sensitivity_score: float
    gate_status: str  # "PASS" | "FAIL"
```

### `v0_evaluator.py`
```python
class GroundTruthEvaluator:
    def evaluate_sample(self, sample: BenchmarkSample) -> ValidationRunResult:
        """Runs sample through E9->E16 pipeline and compares against GroundTruthFinding."""
```

---

## 4. Verification & Certification Protocol

1. Run SHA-256 baseline freeze audit to ensure 84 E9–E16 files have 0% mutation.
2. Execute full V0 validation suite: `python3 -m pytest tests/v0_validation/ -v`.
3. Verify `PYTHONHASHSEED=0` and `PYTHONHASHSEED=42` identity parity.
4. Generate `docs/v0_validation_report.md`.
5. Require human reviewer sign-off before un-blocking Sprint E17.
