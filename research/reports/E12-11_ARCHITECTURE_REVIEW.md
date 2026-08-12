# 07 — E12-11 Architecture Review

**Target**: Review of E12-11 Contextual Dataflow Qualification Proposals  
**Baseline**: TP=20, FN=0, Recall=100%, FP=83  

---

## 1. Component-by-Component Evaluation Matrix

| Proposal / Component | Classification | Pipeline Location | Industry Pattern Comparison | Verdict & Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **1. Value Provenance & Static Query Resolver** | **PARTIALLY SOUND** | Should move to Pre-Dataflow Constant Pass | Semgrep `Constant_propagation.ml` | Currently in `taint_verifier.py`. Must be generalized as a pre-dataflow constant propagation pass to fold static string concats before taint evaluation. |
| **2. Control-Flow Guards & Sanitizer Tracker** | **ARCHITECTURALLY SOUND** | DFG / Sanitizer Guard Layer | Semgrep `pattern-sanitizers` & `solve_precondition` | Matching language guard functions (`escapeshellarg`, `intval`, `filter_var`) and assigning `TaintState.SANITIZED` is standard and effective. |
| **3. Cookie Security Attribute Qualifier** | **ARCHITECTURALLY SOUND** | Decoupled Qualification Layer (`qualifier.py`) | SonarQube / Semgrep Cookie Security Rules | Evaluating `setcookie` arguments for `httponly=true` and `secure=true` to classify `OperationSemantics.SECURE_CONFIGURATION` is sound. |
| **4. Local Resource & Internal Dispatch Qualifier** | **ARCHITECTURALLY SOUND** | Qualification Layer (`qualifier.py`) | CodeQL Path Traversal Provenance | Bounding inclusion paths to local directory constants (`__DIR__`, `DVWA_WEB_PAGE_TO_ROOT`) and tagging `SourceCategory.LOCAL_RESOURCE` is architecturally correct. |
| **5. Sink Category Disambiguation** | **ARCHITECTURALLY SOUND** | Qualification Layer (`qualifier.py`) | Semgrep Sink Category Matching | Rejecting candidates where sink type (`HTML_OUTPUT` vs `FILE_INCLUSION`) does not match rule intent prevents cross-category false positives. |

---

## 2. In-Depth Rationale & Pipeline Positioning

### Component 1: Value Provenance & Static Query Resolver
- **Current Location**: Embedded inside `TaintVerifier._is_static_sql_argument`.
- **Finding**: While effective for simple single-quoted or double-quoted query strings, regex-based argument checking inside `taint_verifier` cannot handle complex multi-variable string concatenations.
- **Recommendation**: Reposition static value folding into an explicit Constant Propagation pass prior to dataflow analysis (similar to Semgrep's `Constant_propagation.ml`), while preserving `_is_static_sql_argument` as a fast AST fallback.

### Component 2: Control-Flow Guards & Sanitizer Scope Detection
- **Current Location**: `TaintVerifier` Step 6B.
- **Finding**: Checking variable assignments for sanitizer wrappers (`$var = escapeshellarg(...)`) correctly identifies neutralized taint paths without hardcoding snippet strings.
- **Recommendation**: Maintain in DFG/TaintVerifier as a generalized sanitizer capability check.

### Component 3: Cookie Security Attribute Qualifier
- **Current Location**: `SemanticFindingQualifier._classify_operation_semantics`.
- **Finding**: Inspecting cookie creation calls for security flags (`secure`, `httponly`) is a pure semantic qualification step.
- **Recommendation**: Retain in `qualifier.py`.

### Component 4: Local Resource & Include Dispatch Qualifier
- **Current Location**: `SemanticFindingQualifier._classify_source_category`.
- **Finding**: Differentiating between dynamic user-controlled path parameters (`$_GET['page']`) and local framework includes (`require_once __DIR__ . '/file.php'`) prevents false-positive LFI alerts while maintaining 100% recall on dynamic path traversal.
- **Recommendation**: Retain in `qualifier.py`.

### Component 5: Sink Category Disambiguation
- **Current Location**: `SemanticFindingQualifier.qualify_candidate`.
- **Finding**: Verifying that a matched AST node (e.g. `echo`) corresponds to the intended sink category (`HTML_OUTPUT`) rejects false matches where rules are misapplied to incompatible sinks.
- **Recommendation**: Retain in `qualifier.py`.
