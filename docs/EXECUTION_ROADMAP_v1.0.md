# KarsaSec v1.0 Roadmap — Decoupled Compiler Pipeline & Code Property Graph (CPG) Platform

Platform: KarsaSec Secure Code Analysis Platform (SecOS)
Versi Roadmap: 4.0.0 (Code Property Graph (CPG) Core Focus) | Status: Milestone 2 Active
Visi Utama: "Evolusi KarsaSec menjadi Compiler Pipeline & CPG SAST Engine berskala enterprise dengan Pass Manager, Universal IR, CFG, SSA, Data Flow Analysis, Intra/Interprocedural Taint Engine, Code Property Graph (CPG), CPG Query Engine, Framework Semantics, Incremental Analysis, dan Enterprise Qualification."

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
Intraprocedural Taint Analysis (TaintGraph)
    │
Interprocedural Taint Analysis (InterproceduralTaintGraph & Function Summaries)
    │
Code Property Graph (CPG Fusion Engine)  <── SINGLE SOURCE OF TRUTH
    │
CPG Query Engine
    │
Framework Semantics (Laravel, Django, Express, Next.js, Spring, ASP.NET)
    │
Incremental Analysis Engine (CPG Delta & Pass Caching)
    │
Enterprise Qualification Platform
    │
Finding Engine → SARIF / JSON / HTML Reports → AI Advisory
```

---

## Strategic Roadmap Phases

### Milestone 2: Semantic Analysis Engine & Enterprise Engine (E5 – E12)
- **Sprint E5 — Data Flow Analysis Engine** (`karsasec/analysis/dataflow/`) [COMPLETED]
- **Sprint E6 — Intraprocedural Taint Analysis** (`karsasec/analysis/taint/`) [COMPLETED]
- **Sprint E7 — Interprocedural Taint Analysis** (`karsasec/analysis/interprocedural/`) [COMPLETED]
- **Sprint E8 — Code Property Graph (CPG) Core** (`karsasec/cpg/`) [ACTIVE]
  - Graph Fusion: AST + IR + CFG + SSA + CallGraph + SymbolGraph + DataFlow + Taint = `CPGGraph`
  - O(1) GraphIndex, Multi-Edge Types, Validation, JSON/Binary Serialization, DOT/Mermaid/HTML Visualizer
- **Sprint E9 — CPG Query Engine** (`karsasec/query/`)
  - Fluent graph query engine matching source-to-sink paths without regex
- **Sprint E10 — Framework Semantic Engine** (`karsasec/analysis/framework/`)
  - Framework Models: Laravel, Django, Express, Next.js, ASP.NET, Spring (`FrameworkModel`)
- **Sprint E11 — Incremental Analysis Engine** (`karsasec/analysis/incremental/`)
  - File Change Detector, CPG Delta, Call Graph Delta, Incremental Pass Scheduler
- **Sprint E12 — Enterprise Qualification Platform** (`karsasec/qualification/`)
  - Benchmark against OWASP Benchmark, Juliet, DVWA, 100 KLOC < 5s performance verification

### Milestone 3: Enterprise SaaS Platform (F1 – F6)
- **Sprint F1**: REST API (`/scan`, `/findings`)
- **Sprint F2**: Worker Queue (Celery/Redis Background Scans)
- **Sprint F3**: Object Storage & Artifact Registry (MinIO / S3)
- **Sprint F4**: Multi-Tenant & RBAC (Organization, Team, Project)
- **Sprint F5**: Git SCM Integration (PR Scan, Commit Scan, Incremental Scan)
- **Sprint F6**: IDE Extensions (VS Code Extension & AI Fix Suggestions)
