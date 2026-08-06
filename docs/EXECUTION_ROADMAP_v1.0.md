# KarsaSec v1.0 Roadmap — Compiler Pipeline & Code Property Graph (CPG) SAST Platform

Platform: KarsaSec Secure Code Analysis Platform (SecOS)
Versi Roadmap: 2.1.0 (Compiler Pipeline & CPG Enterprise Focus) | Status: Milestone 2 Active
Visi Utama: "Evolusi KarsaSec menjadi Compiler Pipeline & Code Property Graph (CPG) SAST Engine berskala enterprise dengan tahapan pipeline linier deterministik dan multi-tenant SaaS readiness."

---

## Linear Compiler Pipeline Architecture

```
Source Code → Language Detection → Tree-sitter Parser → AST → Symbol Resolution → CFG → Call Graph → Dataflow → Taint Analysis → Code Property Graph (CPG) → Rule Engine → Finding Engine → SARIF / HTML / JSON → AI Advisory
```

---

## Strategic Phase & Sprint Schedule

| Fase | Sprint | Fokus Utama | Output & Artifact Utama |
|---|---|---|---|
| **Fase 1** | **Sprint E1** | **Call Graph Engine** | `CallNode`, `CallEdge`, `CallGraphBuilder` (`analysis.callgraph.json`) (**COMPLETED**) |
| | **Sprint E2** | **Symbol Resolution Engine** | `SymbolTable`, `ScopeResolver`, `ImportResolver`, `QualifiedNameResolver` (`analysis.symbol.json`) (**ACTIVE NEXT**) |
| | **Sprint E3** | **CFG Builder Engine** | Basic Block Builder, Control Flow Edges for conditionals/loops/returns (`analysis.cfg.json`) |
| | **Sprint E4** | **Dominator Analysis** | Dominator Tree, Post Dominator, Reachability & Immediate Dominator (`analysis.dominator.json`) |
| **Fase 2** | **Sprint E5** | **Dataflow Analysis** | Def-Use / Use-Def chains, Constant & Copy propagation (`analysis.dataflow.json`) |
| | **Sprint E6** | **Taint Engine** | Intraprocedural Taint propagation tracking (`analysis.taint.json`) |
| | **Sprint E7** | **Interprocedural Analysis** | Cross-function parameter and return value taint tracking (`analysis.interprocedural_taint.json`) |
| **Fase 3** | **Sprint E8** | **Framework Semantic Model** | Framework routing models (Laravel, Django, Flask, FastAPI, Express, Next.js, Gin, Actix, Axum, Spring, ASP.NET) |
| | **Sprint E9** | **Dependency Analyzer** | Lockfile parsing (`package.json`, `composer.json`, `Cargo.toml`, `go.mod`, `pom.xml`, `requirements.txt`) |
| | **Sprint E10**| **Manifest Intelligence** | Automatic framework rule auto-activation based on project manifests |
| **Fase 4** | **Sprint E11**| **Advanced Rule Engine** | Stateful rules, multi-file rules, cross-file & cross-language rules |
| | **Sprint E12**| **Code Property Graph (CPG)** | Unified graph fusion of AST + CFG + CallGraph + Dataflow + Symbol Graph (`cpg.json`) |
| **Fase 5** | **Enterprise**| **Enterprise Capability** | Incremental scan, Parallel analysis, Artifact cache, Baseline management, Full SARIF v2.1.0, CI/CD, SaaS API |
| **Fase 6** | **AI Layer** | **AI Security Copilot** | Post-processing finding explanation, risk prioritization, fix draft, PR review assistant |
