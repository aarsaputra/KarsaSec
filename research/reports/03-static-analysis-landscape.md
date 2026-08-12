# 03 — Static Analysis Ecosystem Landscape Analysis

**Repository**: `analysis-tools-dev/static-analysis`  
**Studied Commit**: `66668c6cc5b2db72d0233033efe7ccf2c489aaf8`  
**Primary Function**: Comprehensive landscape registry of static code analysis tools, linters, and security scanners.

---

## 1. Categorization of SAST Engine Architectures

Analysis of the global static analysis tool ecosystem reveals six distinct architectural paradigms:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        SAST Engine Taxonomy                            │
├───────────────────┬──────────────────────┬─────────────────────────────┤
│ Architecture      │ Examples             │ Characteristics             │
├───────────────────┼──────────────────────┼─────────────────────────────┤
│ 1. Regex / Text   │ Bandit, Flake8-Sec,  │ Fast, zero-parse, high FP,  │
│    Pattern        │ Gitleaks             │ no dataflow or semantics.   │
├───────────────────┼──────────────────────┼─────────────────────────────┤
│ 2. AST Pattern    │ PMD, ESLint,         │ Structural AST matching,    │
│    Matching       │ PHPCS, RuboCop       │ intra-file node inspection, │
│                   │                      │ limited local dataflow.     │
├───────────────────┼──────────────────────┼─────────────────────────────┤
│ 3. Generic AST +  │ Semgrep, CodeQL      │ Unified AST representation, │
│    Taint Engine   │                      │ interprocedural DFG/CFG,    │
│                   │                      │ explicit taint specs.       │
├───────────────────┼──────────────────────┼─────────────────────────────┤
│ 4. Compiler IR /  │ SpotBugs, Infer,     │ Low-level byte/SSA code IR, │
│    Abstract Interp│ Joern, SonarQube     │ precise value tracking,     │
│                   │                      │ path-sensitive analysis.    │
├───────────────────┼──────────────────────┼─────────────────────────────┤
│ 5. Multi-Tool     │ sast-scan, MegaLinter│ Orchestration & SARIF       │
│    Orchestration  │                      │ normalization wrappers.     │
├───────────────────┼──────────────────────┼─────────────────────────────┤
│ 6. Hybrid Graph + │ KarsaSec             │ Tree-sitter / AST parsing,  │
│    Qualification  │                      │ incremental DFG, semantic   │
│                   │                      │ evidence qualification.     │
└───────────────────┴──────────────────────┴─────────────────────────────┘
```

---

## 2. Key Industry Capabilities vs. Precision Trade-Offs

1. **Regex / Syntactic Pattern Matching**:
   - *Strengths*: Blazing fast execution; simple rule definition.
   - *Weaknesses*: Massive False Positive rates; completely blind to variable assignments, control flow, functions, or sanitizers.
2. **AST Pattern Matching**:
   - *Strengths*: Understood code structure (distinguishes comments/strings from call nodes).
   - *Weaknesses*: Cannot follow variable flow across statements or function calls.
3. **Dataflow & Taint Tracking Engines (Semgrep, CodeQL)**:
   - *Strengths*: Tracks untrusted user input from Sources through intermediate assignments to Sinks.
   - *Weaknesses*: High memory/CPU cost for whole-program interprocedural analysis; requires precise sanitizer specs to prevent FPs/FNs.
4. **Abstract Interpretation & SSA-based IR (Infer, Joern)**:
   - *Strengths*: Highly precise path sensitivity, pointer/alias analysis, and constant propagation.
   - *Weaknesses*: Complex rule creation, long compilation times, brittle framework integration.

---

## 3. Position of KarsaSec in the Ecosystem

KarsaSec adopts a **Hybrid AST + Data-Flow Graph + Semantic Qualification Engine** model:
- **Parser Layer**: Tree-sitter AST parsing.
- **Rule Layer**: Declarative YAML pattern rules (OWASP coverage).
- **Graph Layer**: Incremental Data-Flow Analysis (`DataFlowAnalyzer`, `TaintVerifier`).
- **Qualification Layer**: Deterministic finding qualification (`SemanticFindingQualifier`, `FPTaxonomyReason`).

This hybrid approach allows KarsaSec to achieve high precision and speed without the extreme compilation overhead of full bytecode abstract interpreters.
