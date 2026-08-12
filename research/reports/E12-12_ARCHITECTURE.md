# E12-12 Architecture — Pre-Dataflow Constant Propagation Design

**Sprint Target**: Sprint E12-12 (Pre-Dataflow Constant Propagation)  
**Baseline State**: TP=20, FN=0, Recall=100%, FP=83, TN=3 (Post-Sprint E12-11)  
**Primary Objective**: Introduce a formal, reusable `ConstantEvaluator` engine in `karsasec/graph/dataflow/` to fold static expressions and constant variables prior to taint analysis, replacing ad-hoc regex argument checks while maintaining the strict 100% DVWA recall invariant.

---

## 1. System Architecture & Pipeline Positioning

In the existing KarsaSec pipeline, constant verification was fragmented between AST node literal checks and `TaintVerifier._is_static_sql_argument` regexes. Sprint E12-12 establishes an explicit **Pre-Dataflow Constant Propagation Pass**:

```text
Target Code Unit (AST Nodes)
           │
           ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Pre-Dataflow Constant Propagation Pass (`ConstantEvaluator`)           │
│                                                                        │
│ - Traverses AST statements & assignments                               │
│ - Evaluates string literals, concatenations (`.`, `+`), array/consts   │
│ - Assigns ValueLattice state (`CONSTANT`, `UNKNOWN`, `DYNAMIC`)        │
└────────────────────────────────────────────────────────────────────────┘
           │
           ▼
Incremental DFG & Taint State Initialization (`DataFlowAnalyzer`)
   ├── FlowNodeKind.CONSTANT nodes assigned `TaintState.STATIC`
   └── FlowNodeKind.SOURCE nodes assigned `TaintState.TAINTED`
           │
           ▼
Taint Verification (`TaintVerifier`)
           │
           ▼
Decoupled Semantic Qualification (`SemanticFindingQualifier`)
           │
           ▼
Report Generation (SARIF / JSON)
```

---

## 2. Value Lattice Design

The `ConstantEvaluator` operates over a 3-element Value Lattice:

```text
                 UNKNOWN (Top / Conservative Default)
                /       \
      CONSTANT(val)     DYNAMIC / TAINTED (Bottom)
```

### Lattice Definitions:
1. **`CONSTANT(value: str | int | float | bool)`**:
   The expression is provably constant at analysis time.
   *Examples*: `"SELECT * FROM users"`, `"foo" . "bar"`, `$prefix . "/static/path"` (where `$prefix` is constant).
2. **`DYNAMIC` / `TAINTED`**:
   The expression is explicitly bound to untrusted user input or non-static dynamic runtime parameters.
   *Examples*: `$_GET["id"]`, `$_POST["name"]`, `file_get_contents("php://input")`.
3. **`UNKNOWN` (Top / Safety Fallback)**:
   The expression involves unresolved symbols, complex function calls, or un-analyzed control-flow branches.
   *Conservative Invariant*: **`UNKNOWN` != `SAFE`**. If an expression is `UNKNOWN`, taint analysis MUST treat it conservatively as potentially tainted/dynamic to prevent false negatives.

---

## 3. Structural Expression Evaluator Engine

The `ConstantEvaluator` evaluates AST expressions recursively:

### Supported Operations:
- **Literals**: Single-quoted/double-quoted strings, integers, floats, booleans.
- **String Concatenation**:
  - PHP: `$a . $b` -> If both `$a` and `$b` resolve to `CONSTANT`, return `CONSTANT(val_a + val_b)`.
  - JS/Python: `$a + $b` -> Evaluated analogously.
- **Variable Assignments & Propagation**:
  - Maintains a scope symbol table: `env: dict[str, LatticeValue]`.
  - `$x = "a"; $y = $x;` -> `$y` resolves to `CONSTANT("a")`.
- **Constants & Superglobals**:
  - Magics like `__DIR__`, `__FILE__` resolve to `CONSTANT`.
  - Superglobals `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES` resolve to `DYNAMIC`.

### Control-Flow & Cycle Guards:
- **Loop Assignments** (`while`, `for`): Re-assignments within loops default to `UNKNOWN` to avoid infinite propagation.
- **Branch Divergence** (`if`/`else`): If a variable is assigned different constant values in opposing branches, its merged value resolves to `UNKNOWN`.
- **Recursion Guard**: Tracks visited AST nodes in a set to prevent infinite loops on circular assignments (`$x = $x . "a"`).

---

## 4. Interaction with TaintVerifier & Qualifier

1. **`DataFlowAnalyzer`**: Before running dataflow propagation, invokes `ConstantEvaluator.evaluate_node(ast_node)`.
2. **`TaintVerifier`**: Refactored to query `ConstantEvaluator` instead of running fragile regex matching in `_is_static_sql_argument`.
3. **`SemanticFindingQualifier`**: If a sink argument evaluates to `CONSTANT`, the candidate is rejected with `FPTaxonomyReason.STATIC_INPUT` and `QualificationState.REJECTED`.

---

## 5. Non-Goals for Sprint E12-12

- **No Whole-Program Interprocedural Solver**: Sprint E12-12 focuses strictly on intraprocedural file/function scope constant propagation.
- **No Hardcoded String Benchmarks**: The constant evaluator MUST NOT contain string literal checks specific to DVWA or specific database tables. Evaluation MUST be purely structural.
