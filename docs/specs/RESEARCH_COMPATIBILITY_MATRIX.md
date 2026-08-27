# KarsaSec Research & SAST Platform Compatibility Matrix

## Purpose
This document establishes a comparative matrix between KarsaSec and industry-leading static analysis, secret detection, code property graph, and automated remediation platforms. The purpose is to ensure KarsaSec draws architectural inspiration from proven open-source standards while maintaining its deterministic Python-first SAST engine identity.

---

## SAST Platform Comparison Matrix

| Capability / Architecture | KarsaSec (SecOS) | Semgrep | CodeQL | SonarQube | Joern | Gitleaks / Bearer |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **AST Matching Engine** | Implemented (YAML AST) | Implemented (Tree-sitter) | Implemented (QL AST) | Implemented (Sonar AST) | Implemented (CPG) | Regex / AST |
| **Taint Tracking & Guard Check** | Implemented | Implemented (Taint Mode) | Implemented (Dataflow) | Partial | Implemented | N/A |
| **Hybrid Local RAG Context** | Implemented (BM25 + Model2Vec) | N/A | N/A | AI Assistant | N/A | N/A |
| **Call Graph & Scope Resolver** | Implemented | Partial | Implemented | Partial | Implemented | N/A |
| **Code Property Graph (CPG)** | Implemented | N/A | Implemented | N/A | Implemented | N/A |
| **Secret & High-Entropy Engine** | Implemented | Partial | N/A | N/A | N/A | Implemented |
| **IaC Security Engine** | Implemented (Docker/K8s/Actions) | Implemented | N/A | Implemented | N/A | N/A |
| **Automated AST Remediation** | Planned (Sprint A3 / Fix) | Partial | N/A | AI Suggestions | N/A | N/A |
| **CI Quality Gate Baseline** | Implemented (SARIF Diff) | Implemented | Implemented | Implemented | N/A | Implemented |

---

## Architectural Inspiration Roadmap

### 1. Detection Layer (Semgrep & Bearer)
- **YAML Rule Definitions**: Standardized rule metadata, CWE, OWASP, severity, and confidence tags.
- **Pattern Matchers**: AST node pattern matching combined with symbol triggers and regex fallbacks.
- **Framework Autodetect**: Package manager and manifest profiling to activate framework-specific rule packs.

### 2. Analysis Engine Layer (CodeQL, LLVM & Joern)
- **Interprocedural Dataflow**: Source-to-sink dataflow analysis with sanitization and guard checks.
- **Intermediate Representation (IR)**: High-Level (HIR) and Mid-Level (MIR) node representation for language independence.
- **Pass Manager Architecture**: Sequential analysis passes executed over standard workspace artifacts.

### 3. Platform & Developer Experience (SonarQube & Trivy)
- **Quality Gate Integration**: Strict baseline comparisons preventing new security regressions in pull requests.
- **Unified Rule CLI**: `karsasec rules validate`, `karsasec rules lint`, `karsasec rules docs`, and `karsasec rules coverage`.
- **SARIF Standard v2.1.0**: Native export capability compatible with GitHub Code Scanning.

### 4. Automated Code Transformation (OpenRewrite & Comby)
- **Safe Code Refactoring**: Deterministic AST transformations for auto-patching safe fixes.
- **Non-destructive Edits**: Preserving code style, formatting, and inline comments when applying remediations.

### 5. AI Reasoning Layer (Post-Engine Maturity)
- **Ground Truth Guardrail**: AI acts strictly as an explainer and patch reviewer, never as the primary flaw detector.
- **Deterministic Pre-filtering**: SAST engine validates all candidates before handing findings to LLM workflows.
