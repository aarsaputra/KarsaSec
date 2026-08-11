# ADR-0009: Incremental Data-Flow & Taint Analysis Engine

- **Status**: Accepted
- **Date**: 2026-08-11
- **Authors**: KarsaSec Core Architecture Team
- **Deciders**: Lead Architect, Qualification Lead
- **Sprint Context**: Sprint E11 (Incremental Data-Flow & Taint Analysis Engine)

---

## 1. Context and Problem Statement

Following the completion of Sprint E12-2 (DVWA Qualification Baseline), KarsaSec established a deterministic benchmark baseline with **Precision = 4.23%**, **Recall = 60.00%**, and **F1 = 7.89%**.

Root-cause analysis identified 8 False Negatives (FN) on DVWA:
1. **Command Injection (4 FNs)**: Untrusted input assigned to `$target = $_REQUEST['ip']` and passed via concatenation to `shell_exec('ping ' . $target)`.
2. **SQL Injection (2 FNs)**: Multi-path propagation from `$_REQUEST` into `$query` and executed via `$sqlite_db_connection->query($query)`.
3. **LFI Environment Miss (1 FN)**: Variable `$file = $_GET['page']` passed to `include($file)`.
4. **Weak Crypto Context Miss (1 FN)**: `md5($pass)` context disambiguation.

The existing `TaintVerifier` relied primarily on AST node inspection and single-line regex backtracking, failing when variable assignments and string concatenation spanned multiple statements or function calls.

We need a deterministic data-flow engine to resolve variable assignments, concatenation, interprocedural propagation, and sink-aware sanitization without introducing a full general-purpose CFG compiler infrastructure.

---

## 2. Decision Driver Requirements

1. **Deterministic & Local**: Zero AI/LLM/probabilistic inference. 100% AST/source-based and reproducible.
2. **Incremental vs. Full CFG**: Perform light, statement-level Def/Use flow tracking bounded by execution caps rather than building complete control-flow basic blocks.
3. **Sink-Aware Sanitization**: Differentiate sanitizers by sink category (e.g. `htmlspecialchars` protects `HTML_OUTPUT` but NOT `COMMAND_EXECUTION` or `SQL_EXECUTION`).
4. **Bounded Limits**: Enforce `MAX_FLOW_DEPTH`, `MAX_CALL_DEPTH`, `MAX_NODES_VISITED`, and `MAX_ASSIGNMENT_HOPS`. Truncated analysis must yield `UNKNOWN`, never `SAFE`.
5. **Backwards Compatibility**: Fully preserve `ConstantResolver` (E10-3K), `FindingCorrelator`, `Rule Contract`, and `Qualification Engine` (E12-2).

---

## 3. Detailed Architecture Design

### 3.1 Why Incremental Rather Than Full CFG?
Full CFG construction requires computing control-flow edges for complex control structures (loops, exceptions, dynamic dispatch, traits), which introduces high overhead and potential non-determinism.
Incremental Data-Flow analysis operates on AST statement sequences within file/function boundaries:
- Extracting variable definition/assignment nodes (Def).
- Mapping variable reference/expression nodes (Use).
- Following chain edges from Use to Def recursively up to strict bounds.

### 3.2 Data-Flow Representation
Flow graph consists of typed `FlowNode` instances:
- `SOURCE`: Entry points of untrusted input (e.g. `$_GET`, `$_POST`, `$_REQUEST`, `request.args`).
- `ASSIGNMENT`: Variable assignments (`$a = $b`).
- `USE`: Variable reference in expressions.
- `TRANSFORM`: Operations altering value representations (string concatenation `.`, string interpolation).
- `SANITIZER`: Function calls or type coercions attempting to neutralize taint.
- `SINK`: Dangerous function calls or language constructs (`shell_exec`, `query`, `include`).
- `PARAMETER`: Formal function arguments (`function foo($param)`).
- `CALL`: Function invocation (`foo($arg)`).
- `RETURN`: Function return statement (`return $val`).
- `CONSTANT`: Statically resolved constant values (via `ConstantResolver`).
- `UNKNOWN`: Unresolved flow elements.

Every `FlowNode` encapsulates a `SourceLocation(file_path, line, column)` to guarantee precise diagnostic evidence generation.

### 3.3 Definition/Use Representation
The `DefUseExtractor` scans the AST and source text statement-by-statement to construct an intra-procedural symbol map:
```text
Symbol Table Map:
  var_name -> List[AssignmentNode]
```
When a variable reference is encountered at a sink or expression, the `DataFlowAnalyzer` queries the DefUse map for active definitions preceding the use location.

### 3.4 Taint Propagation Model
Taint propagation follows a directed graph search from Sink → Use → Def → Source:
1. **Direct Assignment**: `$a = $_GET['id']` → Tainted (`$a`).
2. **Multi-Hop Assignment**: `$b = $a; $c = $b;` → Tainted (`$c`).
3. **Concatenation**: `$query = "SELECT * FROM users WHERE id = " . $c;` → Tainted (`$query`).
4. **Expression Propagation**: Binary expressions, array indexing, and string interpolation inherit taint from any constituent operands.

### 3.5 Sanitizer Model (`SanitizerRegistry`)
Sanitizers are registered with capability flags mapped to specific sink categories:
- `HTML_ESCAPE` (`htmlspecialchars`, `htmlentities`) → Neutralizes `HTML_OUTPUT`.
- `SHELL_ESCAPE` (`escapeshellarg`, `escapeshellcmd`) → Neutralizes `COMMAND_EXECUTION`.
- `SQL_ESCAPE` (`mysqli_real_escape_string`, `pdo->quote`) → Neutralizes `SQL_EXECUTION`.
- `INTEGER_COERCION` (`intval`, `(int)`, `floatval`) → Neutralizes `SQL_EXECUTION`, `COMMAND_EXECUTION`, `FILE_INCLUSION`.
- `PATH_COMPONENT_NORMALIZATION` (`basename`) → Neutralizes `FILE_INCLUSION` / `PATH_TRAVERSAL`.

If a sanitizer is applied that is **incompatible** with the sink category (e.g. `htmlspecialchars` before `shell_exec`), taint propagation remains active (`TAINTED`).

### 3.6 Sink Model (`SinkRegistry`)
Sinks are grouped into standardized semantic categories:
- `COMMAND_EXECUTION`: `exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`, `eval`.
- `SQL_EXECUTION`: `mysqli_query`, `PDO::query`, `PDO::exec`, `PDOStatement::execute`, `$db->query`.
- `FILE_INCLUSION`: `include`, `require`, `include_once`, `require_once`.
- `FILE_READ`: `file_get_contents`, `readfile`, `fread`.
- `HTML_OUTPUT`: `echo`, `print`, `printf`.
- `CODE_EVALUATION`: `eval`, `assert`, `create_function`.
- `CRYPTOGRAPHIC_OPERATION`: `md5`, `sha1`, `mcrypt_encrypt`.

### 3.7 Function Boundary Model (Bounded Interprocedural)
Function call propagation resolves calls to local function definitions within the same source context:
```php
function execute_ping($ip) {
    shell_exec("ping -c 4 " . $ip);
}
$input = $_GET['ip'];
execute_ping($input);
```
1. Caller argument `$input` is evaluated → `TAINTED`.
2. Parameter `$ip` in `execute_ping` bound to `$input` → `TAINTED`.
3. Parameter `$ip` used in `shell_exec` → `TAINTED` sink match.

### 3.8 Analysis Limits & Bounds
To prevent infinite recursion and catastrophic backtracking on complex or cyclic code:
- `MAX_FLOW_DEPTH`: 10 hops
- `MAX_ASSIGNMENT_HOPS`: 10 assignments
- `MAX_CALL_DEPTH`: 3 calls
- `MAX_NODES_VISITED`: 100 flow nodes
- `Cycle Protection`: Visited variable set tracked during traversal; cycles terminate immediately.

### 3.9 UNKNOWN Semantics
When an analysis cap is exceeded, an unresolved variable is encountered, or a dynamic dispatch cannot be resolved:
- Taint state is marked `UNKNOWN`.
- Evidence captures `truncated=True`.
- Finding confidence is assigned `UNKNOWN` or `POSSIBLE`, ensuring zero silent assumption of safety (`absence of evidence != evidence of safety`).

### 3.10 Compatibility
- **E10-3K**: `ConstantResolver` is invoked first. Static constants (`BASE_PATH . 'foo.php'`) remain `STATIC` and will NOT trigger findings.
- **E10-3J**: Finding confidence isolation preserves separate tracking for `UNKNOWN` states.
- **E12-2**: Ground truth in `benchmarks/dvwa/manifest.yaml` remains strictly untouched. Baseline comparisons in `benchmarks/results/dvwa/` remain reproducible.

---

## 4. Consequences and Verification

### Positive Impacts
- Eliminates 4 Command Injection FNs and 2 SQL Injection FNs on DVWA.
- Reduces False Positives through sink-aware sanitizer validation.
- Provides enterprise-grade propagation path evidence (`Source -> Assign -> Transform -> Sink`).

### Verification Strategy
- **Unit Test Suite**: `tests/unit/graph/` (`test_dataflow.py`, `test_taint_propagation.py`, `test_sanitizers.py`, `test_sink_analysis.py`, `test_interprocedural.py`).
- **Full Pytest Regression**: 100% pass rate on all existing 1297 tests.
- **Ruff Compliance**: Zero lints.
- **Qualification Snapshot**: `karsasec qualify --save-snapshot` on DVWA.
