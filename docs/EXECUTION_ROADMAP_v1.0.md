# KarsaSec v1.0 Roadmap — Decoupled Compiler Pipeline & Code Property Graph (CPG) Platform

Platform: KarsaSec Secure Code Analysis Platform (SecOS)
Versi Roadmap: 5.0.0 (CPG Query Engine Focus) | Status: Milestone 3 Active
Visi Utama: "Evolusi KarsaSec dari pattern matcher menjadi Enterprise Graph-Based SAST Platform dengan CPG Query Engine, Fluent DSL, Query Planner & Optimizer, Legacy Rule Adapter, dan Multi-hop Traversal Engine."

---

## Linear Compiler Pipeline & Semantic Query Architecture

```
Source Code
    │
Tree-sitter AST → Universal IR → CFG → SSA → Data Flow → Intra/Interprocedural Taint
    │
    ▼
Code Property Graph (CPG) Fusion Engine ── (Single Source of Truth)
    │
    ▼
CPG Query Engine (`karsasec/query/`)
    ├── Query Parser & Fluent DSL
    ├── Query Planner & Optimizer (Filter pushdown, index selection)
    ├── Traversal Engine (DFS, BFS, Reachability, Bounded Multi-hop)
    └── Explain Engine (Evidence Builder & Path Proof)
    │
    ▼
Semantic Rule Engine (`karsasec/rules/`)
    ├── Rule Compiler & Runtime
    └── LegacyRuleAdapter (100% backward compatibility for 134+ YAML rules)
    │
    ▼
Finding Engine → SARIF / JSON / Interactive HTML Reports → AI Advisory
```

---

## Strategic Roadmap Phases

### Milestone 3: Semantic Analysis Engine & Enterprise Engine (E5 – E12)
- **Sprint E5 — Data Flow Analysis Engine** (`karsasec/analysis/dataflow/`) [COMPLETED]
- **Sprint E6 — Intraprocedural Taint Analysis** (`karsasec/analysis/taint/`) [COMPLETED]
- **Sprint E7 — Interprocedural Taint Analysis** (`karsasec/analysis/interprocedural/`) [COMPLETED]
- **Sprint E8 — Code Property Graph (CPG) Core** (`karsasec/cpg/`) [COMPLETED]
- **Sprint E9 — CPG Query Engine & Semantic Rule Engine** (`karsasec/query/`, `karsasec/rules/`) [ACTIVE]
  - Query AST, Query Planner & Optimizer, Fluent DSL (`Function`, `Source`, `Sink`, `DATAFLOW`), Multi-hop Traversal, LegacyRuleAdapter (134+ YAML rules), Rule Explanation Engine, Query CLI commands.
- **Sprint E10 — Framework Semantic Engine** (`karsasec/analysis/framework/`, `karsasec/framework/`) [E10-1 ACTIVE]
  - E10-1 Framework Semantic Foundation: FrameworkDefinition, FrameworkRegistry, FrameworkDetector with DetectorResult and Confidence Scoring, Plugin SDK (`karsasec/plugins/frameworks/`), FrameworkResolver, FrameworkCache, FrameworkGraph, FrameworkPass, CLI commands.
- **Sprint E11 — Incremental Analysis Engine** (`karsasec/analysis/incremental/`)
  - File Change Detector, CPG Delta, Call Graph Delta, Incremental Pass Scheduler.
- **Sprint E12 — Enterprise Qualification Platform** (`karsasec/qualification/`)
  - Benchmark against OWASP Benchmark, Juliet, DVWA, 100 KLOC < 5s performance verification.

### Milestone 4: Enterprise SaaS Platform (F1 – F6)
- **Sprint F1**: REST API (`/scan`, `/findings`)
- **Sprint F2**: Worker Queue (Celery/Redis Background Scans)
- **Sprint F3**: Object Storage & Artifact Registry (MinIO / S3)
- **Sprint F4**: Multi-Tenant & RBAC (Organization, Team, Project)
- **Sprint F5**: Git SCM Integration (PR Scan, Commit Scan, Incremental Scan)
- **Sprint F6**: IDE Extensions (VS Code Extension & AI Fix Suggestions)
