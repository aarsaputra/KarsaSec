# E12-12 Implementation Plan — Pre-Dataflow Constant Propagation

**Target Sprint**: Sprint E12-12  
**Status**: Architecture Gate Completed — Ready for Sprint Execution  
**Invariant**: 100% DVWA Recall Invariant (TP=20, FN=0) must be preserved.

---

## 1. Target Files & Component Modifications

### `[NEW] karsasec/graph/dataflow/constant_evaluator.py`
- **Class**: `LatticeKind(StrEnum)` (`CONSTANT`, `DYNAMIC`, `UNKNOWN`)
- **Class**: `LatticeValue` (dataclass holding `kind`, `literal_value`, `provenance_node_id`)
- **Class**: `ConstantEvaluator`
  - `evaluate_expression(node: ASTNode, env: dict[str, LatticeValue]) -> LatticeValue`
  - `build_scope_environment(root_node: ASTNode) -> dict[str, LatticeValue]`
  - `_eval_binary_op(node: ASTNode, env: dict[str, LatticeValue]) -> LatticeValue`
  - `_eval_variable(node: ASTNode, env: dict[str, LatticeValue]) -> LatticeValue`

### `[MODIFY] karsasec/graph/dataflow/model.py`
- Update `FlowNodeKind` or `TaintState` metadata to support attaching `ConstantEvidence` (provenance line, raw string, lattice state).

### `[MODIFY] karsasec/graph/dataflow/analyzer.py`
- Integrate `ConstantEvaluator` into `DataFlowAnalyzer.analyze()`.
- Run `ConstantEvaluator` over file AST before initializing dataflow nodes.
- Mark nodes with `LatticeKind.CONSTANT` as `TaintState.STATIC`.

### `[MODIFY] karsasec/graph/taint_verifier.py`
- Refactor `_is_static_sql_argument` to delegate argument evaluation to `ConstantEvaluator.evaluate_expression()`.
- Preserve fallback AST string matching for single-node string literals.

### `[NEW] tests/unit/graph/test_constant_evaluator_e12_12.py`
- 15 comprehensive unit test categories covering literals, concatenations, variable chains, dynamic inputs, function scopes, and SQL queries.

---

## 2. Sequential Implementation Steps

1. **Step 1**: Create `karsasec/graph/dataflow/constant_evaluator.py` with `LatticeKind`, `LatticeValue`, and AST traversal evaluator.
2. **Step 2**: Create unit tests in `tests/unit/graph/test_constant_evaluator_e12_12.py` for all 15 test categories.
3. **Step 3**: Integrate `ConstantEvaluator` into `DataFlowAnalyzer` in `karsasec/graph/dataflow/analyzer.py`.
4. **Step 4**: Refactor `TaintVerifier._is_static_sql_argument` in `karsasec/graph/taint_verifier.py` to use `ConstantEvaluator`.
5. **Step 5**: Execute full pytest suite (`pytest tests/`) to verify zero test regressions.
6. **Step 6**: Execute DVWA benchmark suite to verify Recall Invariant (TP=20, FN=0, FP reduction).
