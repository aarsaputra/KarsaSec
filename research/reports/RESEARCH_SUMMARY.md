# RESEARCH SUMMARY — SAST Ecosystem Architecture Research (Task E12-R1)

**Task**: E12-R1 SAST Ecosystem Architecture Research  
**Target Repositories Studied**:
1. `ShiftLeftSecurity/sast-scan` (Commit `ae74004b82a41e800c6bc0b6ed05d48da9b8fc6f`)
2. `utkusen/sast-skills` (Commit `db52227eab1043bf122cbff7206fac6708b4d6c9`)
3. `analysis-tools-dev/static-analysis` (Commit `66668c6cc5b2db72d0233033efe7ccf2c489aaf8`)
4. `semgrep/semgrep` (Commit `4fadea628509108b6b8b621236779f37bf52a08e`)
5. `scadastrangelove/awesome-ai-security-tools` (Commit `6a83a27c43895a333c909d2d5d4312b15502d661`)

---

## 1. Executive Summary

A comprehensive, code-level architectural research study was conducted across 5 open-source SAST repositories to identify modern static analysis design patterns, AST parsing architectures, dataflow/taint representations, false-positive reduction strategies, and AI authority boundaries.

The research establishes that KarsaSec's decoupled **Candidate -> DFG Evidence -> Semantic Qualification** architecture is sound and superior in auditability compared to ad-hoc regex matchers. However, to further reduce false positives beyond the E12-11 baseline (TP=20, FN=0, FP=83) toward precision targets without risking recall, KarsaSec should adopt **formal Constant Propagation over Control-Flow Graphs** and **offset-aware LVal taint tracking** prior to semantic qualification.

---

## 2. Global Repository Architecture Comparison

| Dimension | `sast-scan` | `sast-skills` | `semgrep` | KarsaSec |
| :--- | :--- | :--- | :--- | :--- |
| **AST Parsing** | None (Delegated) | LLM Context Reading | Tree-sitter -> `AST_generic` | Tree-sitter -> `ASTNode` |
| **Rules** | External (Tool-specific) | Natural Language Prompts | Declarative YAML + Metavars | Declarative YAML v2 |
| **Taint Tracking** | None | Heuristic LLM Tracing | LVal + Call Trace + Preconditions | Incremental DFG + `TaintVerifier` |
| **Dataflow / CFG** | None | None | `IL.ml` -> `CFG_build.ml` | `DataFlowAnalyzer` |
| **Sanitizers** | Native Tool Handlers | LLM Code Review | `pattern-sanitizers` | `SanitizerCapability` + Guards |
| **Constant Folding**| None | None | `Constant_propagation.ml` | `ConstantResolver` |
| **FP Qualification** | Aggregation / Line Match| LLM Self-Correction | Rule-level suppressions | `SemanticFindingQualifier` |
| **Deduplication** | Line-range Fingerprint | Markdown Header Merge | Range + Metavar Hash | `FindingIdentity` Hash |
| **Reporting** | SARIF / HTML / JSON | Markdown Audit Report | SARIF / JSON / Text | Native SARIF / JSON |
| **AI Role** | None | Autonomous Agent | None | Auxiliary Explanations Only |

---

## 3. Top 10 Architectural Lessons for KarsaSec

1. **Explicit Intermediate Language (IL) for CFG Construction**: Decomposing AST nodes into basic-block IL instructions before dataflow analysis dramatically simplifies control flow and taint propagation.
2. **Abstract Constant Propagation**: Resolving static string concatenations and constant variables before taint evaluation cleanly eliminates static payload false positives.
3. **Decoupled Qualification Layer**: KarsaSec's separation of candidate emission from qualification is architecturally superior to inline filtering for explainability.
4. **Offset-Aware Taint Tracking (`lval`)**: Tracking object field and array index offsets prevents over-tainting complex data structures.
5. **Labeled Taint Preconditions**: Supporting boolean precondition formulas (`requires: A and not B`) enables precise sanitizer neutralization logic.
6. **Unified SARIF Interchange Format**: Standardizing all report outputs to SARIF v2.1.0 ensures seamless CI/CD integration.
7. **Canonical Finding Identity**: Hashing normalized rule IDs, target files, and symbol names provides robust deduplication across scan passes.
8. **Deterministic Authority Boundary**: Deterministic AST/DFG analysis MUST remain authoritative; LLM/AI components should only provide auxiliary context.
9. **Layered Vulnerability Taxonomy**: Structuring analysis around distinct vulnerability classes with clear sink definitions prevents cross-category false positives.
10. **Strict Invariant Guarding**: Benchmark recall regression tests MUST run as hard CI blockers to prevent accidental precision-recall trade-offs.

---

## 4. Top 10 FP-Reduction Lessons

1. **Pre-Dataflow Constant Folding**: Fold string concatenations before taint analysis to suppress false positives on hardcoded SQL or shell queries.
2. **Variable Assignment Sanitizer Scope**: Detect sanitizer wrappers in assignment statements (`$var = escapeshellarg(...)`) and propagate `SANITIZED` state along downstream edges.
3. **Numeric Type Coercion Guards**: Treat explicit integer casting (`(int)`, `intval`) and numeric checks (`is_numeric`) as robust sanitizers for SQL and LFI sinks.
4. **Local Resource Path Bounding**: Tag inclusion paths rooted in local file constants (`__DIR__`, `ROOT`) as `LOCAL_RESOURCE` to reject non-exploitable local includes.
5. **Cookie Security Attribute Inspection**: Validate `secure` and `httponly` boolean parameters in `setcookie` calls to suppress secure configuration alerts.
6. **Sink Category Compatibility Validation**: Reject findings where the detected sink node does not match the rule's target vulnerability class.
7. **Framework Internal Symbol Exclusion**: Exclude static framework constants and superglobals (`$_SERVER['SCRIPT_NAME']`) from untrusted source categorization when used in local contexts.
8. **Sanitizer Scope Boundary Verification**: Ensure sanitizer protection applies to the specific variable reaching the sink.
9. **Deduplication by Semantic Identity**: Group duplicate findings sharing identical source-to-sink paths.
10. **Contextual Guard Pattern Matching**: Recognize switch/case dispatch and static validation guards.

---

## 5. Top 10 Recall Risks (What Must NOT Be Changed Carelessly)

1. **DO NOT suppress inclusion paths containing dynamic variables**: Any `require`/`include` statement containing un-sanitized dynamic variable interpolation (`$page`, `$_GET`) MUST remain flagged.
2. **DO NOT treat string concatenation alone as a sanitizer**: Concatenating variables into SQL strings does NOT neutralize SQL injection.
3. **DO NOT relax untrusted source definitions**: `$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST`, `$_FILES`, and `php://input` MUST always be treated as untrusted sources.
4. **DO NOT over-generalize static query checks**: Only queries with ZERO dynamic variable interpolation may be tagged as static.
5. **DO NOT suppress custom sanitizers without capability verification**: Only sanitizers matching the specific sink category (e.g. `escapeshellarg` for command execution) may neutralize taint.
6. **DO NOT alter DVWA ground-truth benchmark mappings**: The 20 true positive sink locations MUST remain untouched and detectable.
7. **DO NOT bypass dataflow analysis for unknown symbols**: Unresolved symbols in sink calls must default to `UNKNOWN` / `TAINTED` to prevent false negatives.
8. **DO NOT perform rule-ID-specific suppression**: Suppression must be driven by semantic evidence, never by matching specific rule ID strings.
9. **DO NOT assume framework safety without proof**: Never assume framework functions (e.g. `wp_unslash`) sanitize inputs unless explicitly defined in sanitizer rules.
10. **DO NOT trade recall for precision**: The 100% recall invariant (20 TP, 0 FN) is non-negotiable.

---

## 6. Top 10 Things KarsaSec Should NOT Copy

1. **DO NOT copy Subprocess CLI Wrapping without AST context** (from `sast-scan`).
2. **DO NOT copy Unconstrained LLM Vulnerability Discovery** (from `sast-skills`).
3. **DO NOT copy Line-Range String Deduplication** (from `sast-scan`).
4. **DO NOT copy Hardcoded Rule-ID Exception Logic**.
5. **DO NOT copy Unstructured Markdown Finding Reports** (from `sast-skills`).
6. **DO NOT copy Inline Finding Suppression during Taint Traversal** (from Semgrep).
7. **DO NOT copy Non-Deterministic AI Triage Authority**.
8. **DO NOT copy Raw Text Pattern Matching for Dynamic Languages**.
9. **DO NOT copy Benchmark-Specific Hardcoding**.
10. **DO NOT copy Overly Permissive Sanitizer Assumptions**.

---

## 7. E12-11 Assessment & Verdict

**Verdict**: **APPROVE WITH MODIFICATIONS**

The five components proposed in E12-11 (Static Query Provenance, Control-Flow Guards, Cookie Attribute Qualifier, Local Resource Qualifier, Sink Category Disambiguation) are **architecturally sound and validated by external SAST patterns**. 

However, static query provenance should be repositioned as an explicit **Constant Propagation Pass** prior to dataflow analysis, while qualification rules in `qualifier.py` remain the authoritative boundary for semantic classification.

---

## 8. Verification of Zero Production Code Mutation

The git state of the KarsaSec repository was checked before and after research execution. All research artifacts, cloned codebases, and generated reports reside strictly within:
- `research/external-sast/`
- `research/reports/`

No files in `karsasec/`, `rules/`, `tests/`, or `benchmarks/` were modified during this research task.
