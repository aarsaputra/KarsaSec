# KarsaSec v1.0 Roadmap — Decoupled Compiler Pipeline & Code Property Graph (CPG) Platform

Platform: KarsaSec Secure Code Analysis Platform (SecOS)
Versi Roadmap: 2.2.0 (Pass Manager, Universal IR, CFG, SSA & CPG Query Engine Focus) | Status: Milestone 2 Active
Visi Utama: "Evolusi KarsaSec menjadi Compiler Pipeline & CPG SAST Engine berskala enterprise dengan Pass Manager, Universal IR, CFG, Dominance Sanitizer Verifier, SSA Builder, dan CPG Query Engine."

---

## Linear Compiler Pipeline Architecture

```
Source Code
    ↓
Parser Pass (Tree-sitter)
    ↓
Universal IR Pass (IRFunction/IRStatement/IRExpression)
    ↓
Symbol Pass (SymbolGraph)
    ↓
CallGraph Pass (CallGraph)
    ↓
CFG Pass (Control Flow Graph & Validator)
    ↓
Dominator Pass (Immediate Dominator & Sanitizer Dominance)
    ↓
SSA Pass (Static Single Assignment & Phi Nodes)
    ↓
Dataflow Pass (Def-Use / Use-Def Chains)
    ↓
Taint Analysis Pass (Intra & Interprocedural Taint)
    ↓
Code Property Graph Pass (CPG Fusion)
    ↓
Query Engine (CPG Query Matcher)
    ↓
SARIF / HTML / JSON Reports → AI Security Advisory
```

---

## Strategic Phase & Sprint Schedule

| Sprint | Fokus Utama | Priority Level | Deliverable & Artifact Utama |
|---|---|---|---|
| **E1** | **Call Graph Engine** | Completed | `CallNode`, `CallEdge`, `CallGraphBuilder` (`analysis.callgraph.json`) (**COMPLETED**) |
| **E2** | **Symbol Resolution Engine** | Completed | `SymbolTable`, `ScopeResolver`, `ImportResolver` (`analysis.symbol.json`) (**COMPLETED**) |
| **E2.5**| **Pass Manager & Artifact Store**| Sangat Tinggi | `PassManager`, `ArtifactStore`, `AnalysisPass` (`karsasec/core/pipeline/`) (**ACTIVE NEXT**) |
| **E2.6**| **Universal IR Builder** | Sangat Tinggi | Universal Language-Agnostic IR (`karsasec/ir/`) |
| **E3** | **CFG Builder & Validator** | Sangat Tinggi | BasicBlock, CFGEdges, Reachability Validator (`analysis.cfg.json`) |
| **E4** | **Dominator Analysis** | Sangat Tinggi | Dominance Frontier, Sanitizer Dominance Verifier (`analysis.dominator.json`) |
| **E4.5**| **SSA Builder Engine** | Sangat Tinggi | Variable Renaming, Phi Nodes (`analysis.ssa.json`) |
| **E5** | **Dataflow Analysis** | Sangat Tinggi | Def-Use / Use-Def chains, Constant & Copy propagation (`analysis.dataflow.json`) |
| **E6** | **Intraprocedural Taint Engine**| Tinggi | Local scope taint propagation (`analysis.taint.json`) |
| **E7** | **Interprocedural Taint Engine**| Tinggi | Cross-function parameter and return value tracking (`analysis.interprocedural_taint.json`) |
| **E8** | **Framework Semantic Registry**| Tinggi | Routing & framework model semantics (Laravel, Django, Flask, Express, Next.js, Gin, Spring, ASP.NET) |
| **E9** | **Dependency & Manifest Intelligence**| Menengah | Lockfile parsing (`package.json`, `composer.json`, `Cargo.toml`, `go.mod`, `pom.xml`, `requirements.txt`) |
| **E10**| **Framework Auto Resolver** | Menengah | Automatic rule pack auto-activation based on project manifests |
| **E11**| **Rule Engine v2 (Semantic Rules)**| Tinggi | Stateful rules, multi-file rules, cross-file & cross-language rules |
| **E12**| **Code Property Graph (CPG)** | Sangat Tinggi | 3-Layer Graph Fusion: AST Layer + CFG Layer + Semantic Layer (`cpg.json`) |

---

## Milestone 3 Preview: CPG Query Engine

Target pasca-E12 adalah **KarsaSec CPG Query Engine**:
- Menulis rule keamanan kompleks sebagai query deklaratif di atas CPG (serupa CodeQL tetapi dioptimalkan untuk KarsaSec).
- Mengintegrasikan rule multi-file dan cross-language dalam satu CPG query string.
