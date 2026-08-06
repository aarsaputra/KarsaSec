# KarsaSec v1.0 Roadmap — Decoupled Compiler Pipeline & Code Property Graph (CPG) Platform

Platform: KarsaSec Secure Code Analysis Platform (SecOS)
Versi Roadmap: 3.0.0 (Enterprise CPG & Semantic Compiler Engine Focus) | Status: Milestone 2 Active
Visi Utama: "Evolusi KarsaSec menjadi Compiler Pipeline & CPG SAST Engine berskala enterprise dengan Pass Manager, Universal IR, CFG, SSA, Data Flow Analysis, Intra/Interprocedural Taint Engine, Framework Semantics, Dependency Intelligence, CPG Fusion, dan CPG Query Engine."

---

## Linear Compiler Pipeline Architecture

```
Source Code
    │
Language Detection
    │
Tree-sitter AST
    │
Universal IR
    │
Symbol Resolution (SymbolGraph)
    │
Call Graph (CallGraph)
    │
CFG (Control Flow Graph & Validator)
    │
Dominator Analysis (Sanitizer Dominance Verifier)
    │
SSA (Static Single Assignment & Phi Nodes)
    │
Data Flow Analysis (Reaching Definitions & Def-Use / Use-Def Chains)
    │
Taint Analysis (Intraprocedural & Interprocedural TaintGraph)
    │
Framework Semantics (Laravel, Django, Express, Next.js, Spring, ASP.NET)
    │
Dependency Intelligence (DependencyGraph)
    │
Code Property Graph (CPG Fusion)
    │
CPG Query Engine
    │
Rule Engine v3
    │
Finding Engine → SARIF / JSON / HTML Reports → AI Advisory
```

---

## Strategic Roadmap Phases

### Milestone 2: Semantic Analysis Engine & Enterprise Engine (E5 – E12)
- **Sprint E5 — Data Flow Analysis Engine** (`karsasec/analysis/dataflow/`) [ACTIVE]
  - Reaching Definitions, Def-Use / Use-Def Chains, Constant/Copy Propagation, Liveness Analysis, `DataFlowGraph`
- **Sprint E6 — Intraprocedural Taint Analysis** (`karsasec/analysis/taint/`)
  - Source → Sink tracking within functions, Sanitizer verification, `TaintGraph`
- **Sprint E7 — Interprocedural Taint Analysis** (`karsasec/analysis/interprocedural/`)
  - Cross-function tracking, Function Summary, Context Sensitivity, Parameter Mapping
- **Sprint E8 — Framework Semantic Engine** (`karsasec/analysis/framework/`)
  - Framework Models: Laravel, Django, Express, Next.js, ASP.NET, Spring (`FrameworkModel`)
- **Sprint E9 — Dependency Intelligence** (`karsasec/analysis/dependency/`)
  - Automated dependency parser for package.json, Cargo.toml, go.mod, pom.xml, requirements.txt (`DependencyGraph`)
- **Sprint E10 — Code Property Graph (CPG)** (`karsasec/analysis/cpg/`)
  - Graph Fusion: AST + CFG + SSA + CallGraph + SymbolGraph + DataFlow + Taint = `CPG`
- **Sprint E11 — CPG Query Engine** (`karsasec/query/`)
  - Fluent graph query engine matching source-to-sink paths without regex
- **Sprint E12 — Rule Engine v3** (`karsasec/rules/engine_v3.py`)
  - Refactored rule execution operating exclusively on top of CPG

### Milestone 3: Enterprise SaaS Platform (F1 – F6)
- **Sprint F1**: REST API (`/scan`, `/findings`)
- **Sprint F2**: Worker Queue (Celery/Redis Background Scans)
- **Sprint F3**: Object Storage & Artifact Registry (MinIO / S3)
- **Sprint F4**: Multi-Tenant & RBAC (Organization, Team, Project)
- **Sprint F5**: Git SCM Integration (PR Scan, Commit Scan, Incremental Scan)
- **Sprint F6**: IDE Extensions (VS Code Extension & AI Fix Suggestions)
