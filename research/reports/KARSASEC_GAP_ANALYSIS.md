# KARSASEC GAP ANALYSIS — Ecosystem Architecture Comparison

**Target Engine**: KarsaSec Core & Qualification Engine  
**Baseline State**: TP=20, FN=0, Recall=100%, FP=83 (Reduced from 104 in E12-10).  
**Goal**: Identify architectural gaps and precision bottlenecks without sacrificing recall.

---

## 1. 22-Dimension Comparative Matrix

| # | Architectural Dimension | KarsaSec Implementation | External Pattern (Semgrep / sast-scan / sast-skills) | Architectural Difference | Source Evidence | Potential KarsaSec Gap | Confidence Level |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **AST Representation** | Python `ASTNode` tree parsed via Tree-sitter | Generic AST (`ast_generic/AST_generic.ml`) | Semgrep maps language ASTs to functional variant trees | `AST_generic.ml` | Low — KarsaSec AST is adequate | HIGH |
| 2 | **Rule Representation** | Declarative YAML schema v2 (`Rule`, `RuleCondition`) | Declarative YAML schema (Semgrep rules) | Similar YAML structure; Semgrep has rich metavariables | `Rule.ml` | Low — Rule schema is robust | HIGH |
| 3 | **Rule Matching** | Regex pattern matcher + AST node verification | Structural pattern matching over Generic AST | Semgrep matches AST subtrees structurally | `Match_patterns.ml` | Medium — Pre-filtering relies on regex | HIGH |
| 4 | **Metavariable Model** | Regex capture group bindings | Structural AST metavariable bindings (`$VAR`) | Semgrep binds entire AST subtrees to metavariables | `Metavariable.ml` | Medium — AST metavariables allow richer rules | HIGH |
| 5 | **Dataflow Representation**| Incremental DFG (`DataFlowAnalyzer`) | CFG-backed Dataflow Graph (`AST_to_IL.ml` -> `IL.ml`) | Semgrep builds explicit IL and CFG prior to dataflow | `AST_to_IL.ml`, `CFG_build.ml` | **HIGH — KarsaSec lacks explicit IL/CFG** | HIGH |
| 6 | **Taint Representation** | `TaintState` (`STATIC`, `TAINTED`, `SANITIZED`) | LVal + Call Trace + Labeled Taint (`Taint.ml`) | Semgrep tracks field/array offsets (`lval`) & call traces | `Taint.ml` | **HIGH — KarsaSec lacks offset-aware lval tracking** | HIGH |
| 7 | **Source Modeling** | Regex/AST entry point detection (`_untrusted_sources`) | Declarative `pattern-sources` with labels | Semgrep uses labeled sources (`label: A`) | `Rule.ml`, `Taint.ml` | Medium — Source labeling enables preconditions | HIGH |
| 8 | **Sink Modeling** | `SinkCategory` enum (`SQL_QUERY`, `COMMAND_EXEC`) | Declarative `pattern-sinks` with sink requirements | KarsaSec has explicit sink categories & compatibility matrix | `sinks.py`, `qualifier.py` | None — KarsaSec sink modeling is strong | HIGH |
| 9 | **Sanitizer Modeling** | `SanitizerCapability` matrix + regex guards | Declarative `pattern-sanitizers` with label removal | Semgrep removes taint labels when sanitizer matches | `sanitizers.py`, `Taint.ml` | Medium — Sanitizers should emit explicit DFG nodes | HIGH |
| 10 | **Control-Flow Modeling** | Basic switch/if regex inspection in context | Full basic-block CFG (`CFG_build.ml`) | Semgrep builds true control flow graphs | `CFG_build.ml` | **HIGH — Limited path sensitivity in DFG** | HIGH |
| 11 | **Interprocedural Analysis**| Cross-file symbol resolver (`CrossFileSymbolResolver`) | Multi-file call trace propagation (`Taint.ml`) | Both support call graph resolution across modules | `cross_file_symbol.py` | Low — Symbol resolver works well | HIGH |
| 12 | **Path Sensitivity** | Contextual regex boundary checks | CFG branch analysis & guard evaluation | Semgrep evaluates guard logic per CFG branch | `CFG_build.ml` | Medium — Path sensitivity is basic | HIGH |
| 13 | **Constant/Value Propagation**| `ConstantResolver` + `_is_static_sql_argument` | Worklist Fixpoint Solver (`Constant_propagation.ml`) | Semgrep propagates abstract constant values (`svalue`) | `Constant_propagation.ml` | **HIGH — Constant propagation is fragmented** | HIGH |
| 14 | **Symbol Resolution** | Scope-based symbol resolution (`ScopeResolver`) | Symbol table & AST scope indexing | Similar symbol tracking mechanisms | `scope.py` | None — Scope resolution is healthy | HIGH |
| 15 | **Finding Qualification** | Decoupled `SemanticFindingQualifier` | Integrated during taint traversal | KarsaSec decouples candidate emission from qualification | `qualifier.py` | None — Decoupled qualifier is a STRENGTH | HIGH |
| 16 | **Evidence Provenance** | `DataFlowEvidence` + `StructuralEvidence` | `call_trace` (List of token range locations) | KarsaSec provides structured hop-by-hop evidence | `evidence.py`, `Taint.ml` | None — KarsaSec evidence provenance is rich | HIGH |
| 17 | **Finding Deduplication** | `FindingIdentity` (Canonical semantic fingerprint) | AST range + metavariable binding hashing | KarsaSec uses semantic hash key deduplication | `identity.py`, `Report.ml` | None — Deduplication is robust | HIGH |
| 18 | **FP Suppression** | `QualificationState.REJECTED` + `FPTaxonomyReason` | Inline comment suppression & rule exclusions | KarsaSec has explicit taxonomy reasons for rejection | `fp_taxonomy.py` | None — Taxonomy model is excellent | HIGH |
| 19 | **FN Protection** | Mandatory 100% DVWA Recall Invariant | Rule quality test suites | KarsaSec enforces strict zero-FN invariant | `test_dvwa_baseline.py` | None — Invariant enforcement is superior | HIGH |
| 20 | **Baseline Lifecycle** | Snapshot JSON baseline comparison | SARIF fingerprint comparison | Both support baseline regression testing | `baseline.py` | None — Baseline system is healthy | HIGH |
| 21 | **SARIF / Reporting** | Native JSON / SARIF exporter | SARIF v2.1.0 exporter | Standardized SARIF formatting | `reporting/` | None — Reporting is standard | HIGH |
| 22 | **AI Authority Boundary**| Deterministic engine authoritative | Probabilistic LLM / SAST skills | KarsaSec strictly separates deterministic truth from AI | `sast-skills` | None — Deterministic boundary is enforced | HIGH |

---

## 2. Critical E12-11 Root Cause Analysis (Remaining 83 FPs)

Investigation into the remaining **83 false positives** indicates that they are caused by a combination of:

- **Primary Cause (D): Insufficient Value/Constant Propagation**:
  Static string concatenations and constant array configurations (e.g. `$sql = "SELECT " . $col . " FROM " . $table;` where `$col` and `$table` resolve to constants) are not fully folded into constant values before taint verification.
- **Secondary Cause (C): Insufficient Control-Flow Modeling**:
  Sanitization guards inside `if` statements or helper functions are not propagated along CFG edges to downstream sink calls.
- **Tertiary Cause (F): Insufficient Source/Sink Context Disambiguation**:
  Framework internal variables (e.g., `$PHP_SELF`, `$_SERVER['SCRIPT_NAME']`) in include paths are sometimes evaluated as raw untrusted input when they represent local script execution.

---

## 3. FP Pipeline Elimination Boundaries

To avoid bloating `qualifier.py` with ad-hoc heuristics, candidate findings MUST be eliminated at their natural pipeline boundary:

```text
                  Candidate Pipeline & FP Elimination Bounds
                  
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. Pattern Matching Phase                                              │
│    - Eliminate syntactically invalid rule matches.                      │
├─────────────────────────────────────────────────────────────────────────┤
│ 2. Constant Propagation Pass (PRE-DATAFLOW)                            │
│    - Eliminate statically bounded query arguments (FIXES CATEGORY D).   │
├─────────────────────────────────────────────────────────────────────────┤
│ 3. Dataflow & Control Flow Graph (DFG / CFG) Pass                        │
│    - Eliminate sanitized / guarded flows via CFG edges (FIXES CAT C).   │
├─────────────────────────────────────────────────────────────────────────┤
│ 4. Decoupled Semantic Qualification Phase (`qualifier.py`)               │
│    - Eliminate local resource inclusions, secure cookie settings, and  │
│      mismatched sink categories (FIXES CATEGORY F).                      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Existing KarsaSec Strengths
- Decoupled `CandidateFinding` -> `SemanticFindingQualifier` architecture.
- Strongly typed `DataFlowEvidence` and `StructuralEvidence` model.
- Strict 100% DVWA Recall Invariant enforcement (20 TP, 0 FN).
- Explicit `FPTaxonomyReason` rejection taxonomy.

## 2. Existing KarsaSec Weaknesses
- Fragmented constant resolution (`ConstantResolver` + `_is_static_sql_argument`).
- Lack of explicit Intermediate Language (IL) and basic-block Control Flow Graph (CFG).
- Whole-variable taint state without property/array offset tracking (`lval`).

## 3. External Architectural Patterns Worth Adopting
- Pre-Dataflow Abstract Constant Propagation (from Semgrep `Constant_propagation.ml`).
- LVal Base & Offset Taint Tracking (from Semgrep `Taint.ml`).
- Labeled Taint Preconditions & Logical Formula Evaluation (`requires: A and not B`).

## 4. Patterns That Should NOT Be Adopted
- Subprocess CLI Tool Wrapping without AST context (from `sast-scan`).
- Unconstrained LLM Vulnerability Discovery (from `sast-skills`).
- Line-Range String Deduplication (from `sast-scan`).

## 5. Missing Capabilities
- Formal CFG basic-block construction prior to dataflow.
- Offset-level field/index taint propagation.

## 6. False Positive Reduction Opportunities
- Pre-dataflow constant folding to eliminate static string concatenation alerts.
- Propagating assignment sanitizer scope (`$var = escapeshellarg(...)`) along CFG edges.

## 7. False Negative Risks
- Over-generalizing local resource path suppression.
- Treating un-sanitized string concatenation as safe.

## 8. Architectural Risks
- Bloating `qualifier.py` with ad-hoc heuristics instead of fixing pipeline abstractions earlier in DFG/CFG.

## 9. Recommended E12-11 Changes
- Move static query provenance to a Pre-Dataflow Constant Propagation pass.
- Retain cookie security attributes, local resource bounds, and sink disambiguation in `qualifier.py`.
