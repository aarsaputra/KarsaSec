# ADR-0010: Semantic Finding Qualification & Precision Hardening

- **Status**: Accepted
- **Date**: 2026-08-11
- **Authors**: KarsaSec Core Architecture Team
- **Deciders**: Lead Architect, Security Engine Lead, Qualification Lead
- **Sprint Context**: Sprint E12-3 (Semantic Finding Qualification & Precision Hardening)

---

## 1. Context and Problem Statement

Following Sprint E11 (Incremental Data-Flow & Taint Analysis Engine), KarsaSec achieved significant recall gains on the DVWA benchmark:
- **Command Injection Recall**: Increased from **0% to 100%** (4/4 True Positives detected).
- **Path Traversal**: Maintained **100% Precision, 100% Recall, 100% F1**.
- **SQL Injection**: Reached **71% Recall, 100% Precision**.
- **Overall Recall**: Increased from **45.00% to 65.00%** (False Negatives reduced from 11 to 7).

However, qualification analysis revealed that the primary weakness of the engine shifted from *finding vulnerability flows* to **finding precision and candidate qualification**. The scanner produced 251 False Positives (FP) across 260 correlated findings, resulting in a low Precision metric (~4.92%).

Root cause analysis of the FPs identified three major failure modes:
1. **Lexical Snippet Matches (`LEXICAL_ONLY` / `COMMENT_OR_STRING_MATCH`)**: Rules triggered on code comments (`//`, `/*`, `#`), string literals, documentation, and HTML form inputs without checking whether the candidate was inside executable code.
2. **Unconstrained Auxiliary Rules (`UNCONSTRAINED_SINK`)**: Security helper rules (e.g. `KS-OWASP-0007`) matched broad textual keywords (`"login"`, `"password"`, `"authenticate"`) everywhere in files without requiring taint evidence or executable AST call context.
3. **Implicit Candidate Elevation**: Every raw AST/Rule match was immediately elevated into an authoritative `Finding` without undergoing a multi-stage semantic qualification process.

---

## 2. Decision Driver Requirements

1. **Strict Architectural Invariants**:
   - **Ground Truth Integrity**: `benchmarks/dvwa/manifest.yaml` and `baseline.json` remain strictly immutable. Ground truth is never modified or reduced to alter scanner scores.
   - **Zero Project-Specific Logic**: No project or file-specific exceptions (`if "dvwa" in ...`, `if "low.php" ...`). All qualifications must be 100% generic.
   - **No Artificial Precision Inflation**: Precision must not be raised by deleting rules, suppressing files, or ignoring directories.
   - **Recall Protection**: E11 recall gains (Command Injection = 100%, Path Traversal = 100%, SQL Injection >= 71%, Overall Recall >= 65%) must be preserved.
   - **Determinism**: Identical source code and rule pack must produce identical candidate findings, qualified findings, fingerprints, classification, and metrics.

2. **Multi-Stage Candidate vs Qualified Pipeline**:
   Separate raw rule matching (`CandidateFinding`) from authoritative finding emission (`QualifiedFinding`).

3. **False Positive Taxonomy Engine**:
   Categorize every rejected candidate finding with an explicit, deterministic rejection reason rather than silently dropping candidate matches.

---

## 3. Detailed Architecture Design

### 3.1 Candidate vs Qualified Finding Pipeline

```text
       AST Matcher / Rule Engine
                  │
                  ▼
           CandidateFinding
                  │
                  ▼
     Evidence Enrichment Layer
  (AST Context, Lexical Check, Source)
                  │
                  ▼
       Semantic Sink Validation
     (Function Call vs Comment/String/HTML)
                  │
                  ▼
       Taint-to-Sink Compatibility
     (Source Category + Taint State)
                  │
                  ▼
     Sanitizer Compatibility Matrix
   (Sanitizer Capability vs Sink Category)
                  │
                  ▼
        Semantic Qualification
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
 QualifiedFinding     Rejected Candidate
        │            (FP Taxonomy Reason)
        ▼                   │
 FindingCorrelator          ▼
 (Exact & Semantic)   Rejection Telemetry
        │
        ▼
   Final Finding
```

### 3.2 Candidate Finding (`CandidateFinding`)
A `CandidateFinding` represents an initial match emitted by rule matcher prior to full semantic verification. It carries:
- `rule_id`, `rule_category`, `required_evidence`
- `file_path`, `line`, `column`
- `snippet`, `node_type`, `ast_node`
- `target_language`

### 3.3 Semantic Finding Evidence (`FindingEvidence`)
Enriches candidates with provenance data:
- `sink_symbol`, `sink_category`
- `source_symbol`, `source_category`
- `taint_state` (`TAINTED`, `SANITIZED`, `STATIC`, `UNKNOWN`)
- `constant_resolution` (`STATIC_LITERAL`, `DERIVED_STATIC`, `TAINTED`, `UNKNOWN`)
- `sanitizer_symbol`, `sanitizer_capability` (`SHELL_ESCAPE`, `SQL_ESCAPE`, `HTML_ESCAPE`, `INTEGER_COERCION`)
- `taint_path` (Tuple of `TaintPathHop`)

### 3.4 False Positive Taxonomy (`FPTaxonomyReason`)
Every candidate finding that fails qualification is assigned an explicit rejection category:
1. `LEXICAL_ONLY`: Match occurred inside code comment, documentation, string literal, or HTML markup.
2. `COMMENT_OR_STRING_MATCH`: Specific comment delimiter (`//`, `/*`, `#`) or quoted text match.
3. `UNCONSTRAINED_SINK`: Match keyword present but not invoked as an actual functional sink.
4. `UNTAINTED_INPUT`: Argument is un-tainted and rule requires user input.
5. `STATIC_INPUT`: Argument resolves entirely to static literals or constants.
6. `SANITIZED_INPUT`: Argument neutralized by a sink-compatible sanitizer.
7. `WRONG_SINK_CATEGORY`: Sink capability does not match the rule's target vulnerability category.
8. `WRONG_SANITIZER`: Sanitizer present is incompatible with the sink category (e.g. `htmlspecialchars` for `COMMAND_EXECUTION`).
9. `WRONG_RULE_SCOPE`: Candidate violates AST node type or scope constraint.
10. `DUPLICATE_SEMANTIC_FINDING`: Candidate deduplicated by `FindingCorrelator` as a semantic duplicate.
11. `CONFLICTING_EVIDENCE`: Taint or constant evidence contradicts finding hypotheses.
12. `UNKNOWN_FLOW`: Analysis truncated or inconclusive without required taint evidence.

### 3.5 Taint-to-Sink & Sanitizer Compatibility Matrix (`CompatibilityRegistry`)
Matrix validation enforced by `CompatibilityRegistry`:

| Source Category | Sink Category | Taint State | Qualification Outcome |
| :--- | :--- | :--- | :--- |
| `USER_INPUT` | `COMMAND_EXECUTION` | `TAINTED` | **QUALIFIED** |
| `USER_INPUT` | `SQL_EXECUTION` | `TAINTED` | **QUALIFIED** |
| `USER_INPUT` | `FILE_INCLUSION` | `TAINTED` | **QUALIFIED** |
| `CONSTANT` / `STATIC` | Any Sink | `STATIC` | **REJECTED** (`STATIC_INPUT`) |
| Any Source | `COMMAND_EXECUTION` | `SANITIZED` (`SHELL_ESCAPE`) | **REJECTED** (`SANITIZED_INPUT`) |
| Any Source | `COMMAND_EXECUTION` | `TAINTED` (`HTML_ESCAPE`) | **QUALIFIED** (Incompatible Sanitizer) |
| Any Source | `SQL_EXECUTION` | `SANITIZED` (`SQL_ESCAPE`) | **REJECTED** (`SANITIZED_INPUT`) |

---

## 4. Consequences and Verification

### Positive Impacts
- Eliminates non-executable lexical and string false positives across all rules.
- Significantly increases precision without sacrificing Sprint E11 recall.
- Provides full transparency into candidate rejection through deterministic telemetry.
- Hardens finding correlation to prevent redundant cross-rule overlaps.

### Verification Strategy
- **Unit Test Suite**: `tests/unit/graph/` (`test_semantic_qualification.py`, `test_sink_compatibility.py`, `test_candidate_finding.py`, `test_fp_taxonomy.py`, `test_semantic_correlation.py`).
- **Qualification Test Suite**: `tests/qualification/test_precision_hardening.py`.
- **DVWA Qualification Snapshot**: Dual execution against DVWA benchmark to verify 100% canonical JSON determinism.
