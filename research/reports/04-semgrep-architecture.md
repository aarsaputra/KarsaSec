# 04 — Semgrep Core Architecture & Engine Analysis

**Repository**: `semgrep/semgrep`  
**Studied Commit**: `4fadea628509108b6b8b621236779f37bf52a08e`  
**Primary Language**: OCaml (Core Engine) / Python (CLI Wrapper)  
**License**: LGPL-2.1 (Core Engine)  

---

## 1. Executive System Architecture

Semgrep is a polyglot, semantic static analysis engine that evaluates declarative YAML pattern rules against source code. Unlike naive regex matchers, Semgrep parses target source code into a standardized, language-agnostic **Generic AST (`AST_generic.ml`)**, constructs an **Intermediate Language (`IL.ml`)** for Control Flow Graph (`CFG_build.ml`) analysis, performs abstract constant propagation (`Constant_propagation.ml`), and executes interprocedural taint analysis (`Taint.ml`, `OSS_dataflow_tainting.ml`).

```text
Source Code File (PHP, Python, JS, Go, Java, etc.)
        │
        ▼
Tree-Sitter / Native Parsers (`src/parsing/Parse_target.ml`)
        │
        ▼
Generic AST (`src/ast_generic/AST_generic.ml`)
        │
        ├──► Pattern Matching Engine (`src/matching/Match_patterns.ml`)
        │       ├── Metavariable Binding ($VAR, ...)
        │       └── Structural Expression Matching
        │
        ▼
Intermediate Language Converter (`src/analyzing/AST_to_IL.ml`)
        │
        ▼
Control Flow Graph Builder (`src/analyzing/CFG_build.ml`)
        │
        ▼
Abstract Constant Propagation (`src/analyzing/Constant_propagation.ml`)
        │
        ▼
Data-Flow Taint Propagation Engine (`src/tainting/OSS_dataflow_tainting.ml`)
        │       ├── Taint LVal / Offset Tracking (`Taint.ml`: `lval`, `offset`)
        │       ├── Taint Call Trace (`Taint.ml`: `call_trace`)
        │       └── Labeled Taint Preconditions (`Taint.ml`: `solve_precondition`)
        │
        ▼
Finding Generation & Deduplication (`src/reporting/Report.ml`)
```

---

## 2. Deep Component & Code Analysis

### A. Parsing & Generic AST Representation (`src/ast_generic/`, `src/parsing/`)
- **Module**: `src/ast_generic/AST_generic.ml`, `src/parsing/Parse_target.ml`
- Semgrep uses Tree-sitter parsers for multi-language support. AST nodes from diverse programming languages are mapped into a single unified type definition (`AST_generic.expr`, `AST_generic.stmt`, `AST_generic.pattern`).
- **Benefit**: Pattern rules defined for one construct (e.g. function call `foo(...)`) work across languages without custom parsers per language.

### B. Pattern Matching & Metavariable Binding (`src/matching/`)
- **Module**: `src/matching/Match_patterns.ml`, `src/matching/Metavariable.ml`
- Patterns match AST nodes structurally rather than textually.
- Metavariables (e.g. `$X`, `$...ARGS`) capture AST subtrees during matching.
- Bindings are stored in a metavariable environment `env: (metavar * AST_generic.any) list`.

### C. Intermediate Language (IL) & Control Flow Graph (`src/analyzing/`)
- **Modules**:
  - `src/analyzing/AST_to_IL.ml`: Translates AST nodes into basic-block-friendly IL instructions.
  - `src/analyzing/CFG_build.ml`: Builds intraprocedural Control Flow Graphs (CFG) from IL.
  - `src/analyzing/Constant_propagation.ml`: Implements a fixpoint worklist algorithm (`Dataflow_core.ml`) to track literal values (`Dataflow_svalue.ml`) across CFG edges.
- **FP Reduction Impact**: Constant propagation enables Semgrep to resolve expressions like `$x = "select * from " . "users"; query($x);` to a purely static string, avoiding false-positive SQLi alerts.

### D. Taint & Dataflow Engine (`src/tainting/`)
- **Modules**: `src/tainting/Taint.ml`, `src/tainting/OSS_dataflow_tainting.ml`
- **Taint Representation**:
  ```ocaml
  type lval = { base: base; offset: offset list }
  type offset = Ofld of IL.name | Oint of int | Ostr of string | Oany
  type source = { call_trace: R.taint_source call_trace; label: string; precondition: (taint list * R.precondition) option }
  type taint = { orig: orig; rev_tokens: rev_tainted_tokens }
  ```
- **LVal / Base / Offset Tracking**: Semgrep tracks variable bases (`BVar`, `BThis`, `BArg`) and field/array offsets (`Ofld`, `Ostr`, `Oint`).
- **Labeled Taint & Preconditions**: Supports complex taint specifications such as `requires: A and not B`. Preconditions are evaluated dynamically via `solve_precondition` to verify if a sanitizer label `B` has neutralized taint label `A`.
- **Call Trace Provenance**: `call_trace` records exact propagation steps across function boundaries (`PM` -> `Call`).

---

## 3. False Positive & False Negative Mechanics in Semgrep

| Mechanism | Semgrep Implementation File | How it Eliminates False Positives |
| :--- | :--- | :--- |
| **`pattern-sanitizers`** | `src/tainting/OSS_dataflow_tainting.ml` | Intercepts taint propagation when an expression matches a sanitizer pattern. |
| **`pattern-not` / `pattern-not-inside`** | `src/matching/Match_patterns.ml` | Filters out candidates enclosed within safe guard structures (e.g. `if (is_numeric($X)) { ... }`). |
| **Constant Propagation** | `src/analyzing/Constant_propagation.ml` | Resolves statically bounded values, suppressing alerts on non-user-controlled inputs. |
| **Labeled Taint Preconditions** | `src/tainting/Taint.ml` (`solve_precondition`) | Solves boolean formula `requires: A and not B`, suppressing findings if sanitizer label `B` is present on flow. |
| **Exact Token Location Deduplication** | `src/reporting/Report.ml` | Deduplicates findings matching identical AST node ranges and metavariable bindings. |

---

## 4. Architectural Comparison: Semgrep vs. KarsaSec

| Feature / Dimension | Semgrep Implementation | KarsaSec Implementation | Architectural Comparison |
| :--- | :--- | :--- | :--- |
| **AST Parser** | Tree-sitter -> `AST_generic.ml` (OCaml) | Tree-sitter -> `ASTNode` (Python dataclass) | Both use Tree-sitter; Semgrep maps to functional variant trees. |
| **IR Representation** | `IL.ml` (Intermediate Language) | `UniversalIR` / `FlowNode` | Semgrep translates AST to explicit IL before CFG construction. |
| **CFG Engine** | `CFG_build.ml` (Full intraprocedural CFG) | Incremental DFG (`DataFlowAnalyzer`) | Semgrep builds full basic-block CFGs; KarsaSec uses incremental DFG. |
| **Constant Propagation** | Fixpoint solver (`Dataflow_core.ml`) | `ConstantResolver` + `_is_static_sql_argument` | Semgrep uses abstract interpretation over CFG; KarsaSec uses AST/DFG resolution. |
| **Taint Preconditions** | Boolean logic (`A and not B`) | `TaintState` (`TAINTED`, `SANITIZED`, `STATIC`) | Semgrep handles multi-label formula matching; KarsaSec uses explicit state enums. |
| **Finding Qualification** | Inline during taint traversal | Decoupled `SemanticFindingQualifier` | KarsaSec separates candidate generation from qualification. |

---

## 5. Key Architectural Lessons for KarsaSec

### Patterns KarsaSec SHOULD Adopt
1. **Formal Intermediate Language (IL) for CFG/Dataflow**: Translating AST nodes into an explicit IL before running dataflow analysis decouples parsing quirks from dataflow evaluation.
2. **Abstract Constant Propagation over Control Flow**: Running a formal constant propagation pass prior to taint analysis cleanly eliminates static string false positives early in the pipeline.
3. **Offset-Aware Taint Tracking (`lval` offset)**: Tracking property/array offsets (`$var['key']`) prevents over-tainting unrelated properties of complex objects.

### Patterns KarsaSec SHOULD NOT Copy
1. **Single-Pass Inline Finding Filtering**: Mixing rule pattern matching directly into finding emission makes auditability and candidate provenance tracking difficult. KarsaSec's decoupled candidate -> qualification lifecycle is superior for explainability.
