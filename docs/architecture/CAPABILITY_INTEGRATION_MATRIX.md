# Capability Integration Matrix & Artifact Ownership Contract

Dokumen ini mendefinisikan secara eksplisit **hubungan masukan-keluaran (input-output matrix)** dan **aturan kepemilikan artifak (artifact ownership & immutability)** di seluruh subsistem KarsaSec.

---

## 1. Capability Integration Matrix

| Capability Pass | Input Required | Primary Output Artifact | Primary Consumer | Failure Fallback Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **ParserPass** | Source File Stream | `AST` (FileNode) | `HIRPass`, `SymbolStore` | Skip file, log diagnostic warning, continue scan |
| **HIRPass** | `AST` | `HIR` (High-Level IR) | `MIRPass` | Fallback to streaming token regex matching |
| **MIRPass** | `HIR` | `MIR` (Semantic Program Model) | `CFGPass`, `QueryEngine` | Fallback to HIR pattern matching |
| **CFGPass** | `MIR` | `CFG` (Basic Blocks & Edges) | `DataflowPass` | Fallback to intra-block linear execution |
| **DataflowPass** | `CFG`, `SymbolStore` | `LIR` (Taint Graph / Edges) | `RuleEngine` | Fallback to local AST sink matching |
| **RuleEngine** | `MIR`, `LIR`, `ArtifactStore` | `Finding` Collection | `EvidenceCollector` | Skip failing rule, evaluate remaining rule set |
| **EvidenceEngine**| `Finding`, Source Code | `Evidence` & Confidence | `SARIFReporter` | Default to confidence `MEDIUM` |

---

## 2. Artifact Ownership & Lifecycle Governance

| Artifact Name | Owner Module | Immutability | Cache Strategy | Persistence |
| :--- | :--- | :--- | :--- | :--- |
| `AST` | `karsasec.parser` | Frozen (`True`) | Hash-keyed (`.karsasec/cache/ast`) | Optional Disk |
| `HIR` | `karsasec.ir` | Frozen (`True`) | In-Memory Session | In-Memory |
| `MIR` | `karsasec.ir` | Frozen (`True`) | In-Memory Session | In-Memory |
| `LIR` | `karsasec.ir` | Frozen (`True`) | In-Memory Session | In-Memory |
| `SymbolIndex` | `karsasec.index` | Append-Only Store | SQLite / Persistent Store | Disk Persisted |
| `CFG` | `karsasec.graph` | Frozen (`True`) | In-Memory Session | In-Memory |
| `Findings` | `karsasec.rules` | Frozen (`True`) | No Cache | Persistent Baseline / SARIF |
