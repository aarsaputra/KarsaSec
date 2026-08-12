# E12-12 Test Plan — Constant Propagation Test Suite

**Sprint Target**: Sprint E12-12  
**Test Suite Target**: `tests/unit/graph/test_constant_evaluator_e12_12.py`  
**Safety Threshold**: TP=20, FN=0, Recall=100% (DVWA Benchmark Invariant)

---

## 1. 15 Required Unit Test Categories

| # | Test Category | Target Code Snippet | Expected Lattice State | Expected Evaluation |
| :-: | :--- | :--- | :--- | :--- |
| 1 | **Literal Constant** | `"SELECT * FROM users"` | `CONSTANT` | `"SELECT * FROM users"` |
| 2 | **Constant Concatenation** | `"foo" . "bar"` | `CONSTANT` | `"foobar"` |
| 3 | **Constant Variable** | `$x = "a"; $y = $x;` | `CONSTANT` | `"a"` |
| 4 | **Constant Chain** | `$a = "1"; $b = $a; $c = $b . "2";` | `CONSTANT` | `"12"` |
| 5 | **Dynamic Variable** | `$x = $_GET['id']` | `DYNAMIC` | Tainted Dynamic Source |
| 6 | **Mixed Constant + Dynamic**| `$x = "SELECT * FROM users WHERE id=" . $_GET['id']` | `DYNAMIC` | Contains Dynamic Component |
| 7 | **GET/POST Source** | `$_POST['name']` | `DYNAMIC` | Tainted Dynamic Source |
| 8 | **Constant Function Arg** | `strlen("static")` | `CONSTANT` | Arg resolves to Constant |
| 9 | **Unknown Function Result** | `some_func()` | `UNKNOWN` | Fallback Conservative State |
| 10 | **Branch Assignment** | `if ($c) { $x = "a"; } else { $x = "b"; }` | `UNKNOWN` | Divergent Branch Values |
| 11 | **Loop Assignment** | `while(...) { $x .= "a"; }` | `UNKNOWN` | Loop Re-assignment Guard |
| 12 | **Variable Reassignment** | `$x = "a"; $x = $_GET['b'];` | `DYNAMIC` | Overwritten by Dynamic Input |
| 13 | **Scope Isolation** | `function foo() { $x = "a"; } function bar() { echo $x; }` | `UNKNOWN` | Isolated Symbol Table |
| 14 | **SQL Static Query** | `query("SHOW COLUMNS FROM users")` | `CONSTANT` | Provably Static Query |
| 15 | **SQL Dynamic Query** | `query("SELECT * FROM users WHERE id=" . $id)` | `DYNAMIC` (if `$id` dynamic) | Flagged for Taint Analysis |

---

## 2. DVWA Baseline & Safety Invariant Regression Suite

The test plan mandates running the following automated validation commands after implementation:

```bash
# 1. Unit Tests for Constant Evaluator
pytest tests/unit/graph/test_constant_evaluator_e12_12.py -v

# 2. Existing Contextual Qualification & Evidence Suites (E12-9, E12-10, E12-11)
pytest tests/unit/graph/test_contextual_qualification_e12_11.py -v
pytest tests/unit/graph/test_structural_evidence_e12_10.py -v
pytest tests/unit/graph/test_precision_evidence_e12_9.py -v

# 3. Full Repository Test Suite
pytest tests/ -v

# 4. DVWA Benchmark Recall Verification
python -m benchmarks.evaluate --benchmark dvwa
```

### Safety Requirement:
- **TP Must Equal 20**
- **FN Must Equal 0**
- **Recall Must Equal 100%**
- If TP drops below 20 or FN rises above 0, the sprint implementation MUST be reverted immediately.
