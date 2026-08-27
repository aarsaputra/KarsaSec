# Knowledge Regression Isolation Report (INV-G5.4-04)

## Comparison Checker
- **Module**: `karsasec/benchmark/knowledge_regression.py`
- **Test**: `tests/benchmark/test_g5_knowledge_regression.py`

---

## Regression Criteria
Fails with `KNOWLEDGE_EXPANSION_REGRESSION` if any certified metric ($Recall$, $Precision$, $Specificity$, $EDC$) decreases or if $FPR$ increases.
