# KarsaSec v1.0 Roadmap — Milestone 2: Analysis Engine Evolution

Platform: KarsaSec Secure Code Analysis Platform (SecOS)
Versi Roadmap: 2.0.0 (Semantic Analysis Engine & Interprocedural Taint Focus) | Status: Milestone 2 Active
Visi Utama: "Evolusi KarsaSec dari rule-based SAST scanner menjadi Semantic Static Analysis Platform kelas enterprise dengan Interprocedural Taint Analysis, Call Graph, CFG, Dataflow Engine, Symbol Resolver, dan Framework Semantic Model."

---

## Milestone 2 Execution Schedule (Analysis Engine Evolution)

| Sprint | Fokus Utama | Target Deliverable & Artifact |
|---|---|---|
| **Sprint E1** | **Call Graph Engine** | `CallGraph`, `CallNode`, `CallEdge`, `CallGraphBuilder` (`analysis.callgraph.json`) (**ACTIVE NEXT**) |
| **Sprint E2** | **Symbol Resolution Engine** | `SymbolResolver` for imports, assignments, aliases (`analysis.symbol.json`) |
| **Sprint E3** | **CFG Builder Engine** | Basic Block Builder, Control Flow Edges for conditionals/loops/returns (`analysis.cfg.json`) |
| **Sprint E4** | **Dominator Analysis** | Dominator Tree, Post Dominator, Reachability & Dead Branch Detection (`analysis.dominator.json`) |
| **Sprint E5** | **SSA Preparation** | Variable versioning, assignment tracking, phi candidates (`analysis.ssa.json`) |
| **Sprint E6** | **Dataflow Engine** | Constant propagation, copy propagation, Def-Use / Use-Def chains (`analysis.dataflow.json`) |
| **Sprint E7** | **Interprocedural Taint Analysis** | Cross-function parameter and return value taint propagation (`analysis.taint_graph.json`) |
| **Sprint E8** | **Sanitizer Engine** | Sanitizer Registry (SQL, HTML escape, URL encode, shell escape) |
| **Sprint E9** | **Confidence Scoring Engine** | Multi-factor confidence formula (AST + Taint + CFG + Framework + Sanitizer) |
| **Sprint E10** | **Framework Semantic Model** | Route to controller/middleware/model semantics (Laravel, Django, Flask, Express, Next.js, Gin, Actix, Axum) |
| **Sprint E11** | **Unified Analysis Bundle** | Single `AnalysisBundle` container integrating all engine passes |
| **Sprint E12** | **Engine Qualification Platform** | `karsasec qualification run` benchmarked against OWASP Benchmark, Juliet, DVWA, Juice Shop |

---

## Downstream Pipeline (Capability-Based Language & Secret Packs)

1. **Capability Pack: Language Expansion** (C#, C++, HTML Expansion)
2. **Capability Pack: Multi-Cloud IaC (110 Rules Target)** (Docker: 15, K8s: 25, TF AWS: 20, TF Azure: 15, TF GCP: 15, Helm: 10, GHA: 10)
3. **Capability Pack: Software Composition Analysis (SCA)** (Dependencies: `package-lock.json`, `composer.lock`, `go.sum`, `Cargo.lock`, `pom.xml`)
4. **Capability Pack: Standalone Secret Detection Engine** (Regex → Entropy → Checksum → Context Validator → Confidence score)
5. **Capability Pack: License Compliance Analysis** (GPL, AGPL, LGPL, MIT, Apache, BSD, MPL)
6. **Milestone C: AI Advisory & Remediation Layer** (Explain Findings, Risk Prioritization, PR Security Copilot)
