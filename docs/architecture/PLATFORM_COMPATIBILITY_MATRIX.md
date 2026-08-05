# KarsaSec Platform Compatibility Matrix (v1.0 Production Freeze)

## Overview
Dokumen ini mendokumentasikan skema kompatibilitas versi antarmodul KarsaSec v1.0. Setiap modul mengikuti aturan antarmuka versi formal untuk mencegah breaking change saat integrasi.

---

## 1. Module Compatibility Matrix

| Component | Target Version | Compatible Input Versions | Required Schema / Contract | Failure Behaviour |
| :--- | :--- | :--- | :--- | :--- |
| **Parser Plugins** | v1.0.0 | Source Bytes v1.0 | `ParsedDocument.md` | Fallback to `GenericParserPlugin` |
| **HIR Builder** | v1.0.0 | ParsedDocument v1.0 | `HIR.md` | Wrap broken node in `HIRUnknownNode` |
| **MIR Builder** | v1.0.0 | HIR v1.0 | `MIR.md` | Emit `MIRNop` |
| **CFG Builder** | v1.0.0 | MIR v1.0 | `CFG.md` | Single entry block guarantee |
| **CallGraph Builder**| v1.0.0 | MIR v1.0, AST v1.0 | `CallGraph.md` | Log unresolved call site |
| **Dataflow Engine** | v1.0.0 | CFG v1.0, SymbolTable v1.0 | `Dataflow.md` | Ignore orphan variables |
| **Rule Engine** | v2.0.0 | Rule Schema v2, AST v1.0 | `RuleSchemaV2` | Skip incompatible rules |
| **Reporters** | v1.0.0 | ExecutionResult v1.0 | `Finding.md` | Stream fallback console error |
| **Plugin SDK** | v1.0.0 | CapabilityManifest v1.0 | `SDK_CONTRACT.md` | Reject registration at boot |

---

## 2. Deprecation & Breaking Change Policy
1. **Experimental Phase**: Modul bertanda `EXPERIMENTAL` dapat mengalami pergeseran API minor.
2. **Stable Phase (v1.0)**: Seluruh API publik bertanda `@stable` dalam `API_SNAPSHOT_v1.0.json` tidak boleh diubah tanpa revisi major semver (v2.0).
