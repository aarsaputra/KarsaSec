# Phase 8 — Cross-Dataset Analysis Report (G5.2 External Validation)

## Audit Overview
Documenting real cross-dataset execution results across dataset quality tiers.

---

## Cross-Dataset Execution Matrix

| Tier | Dataset | Status | Evaluated N | Strict Precision (95% CI) | Strict Recall (95% CI) | EDC (95% CI) | Rationale / Provenance |
|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---|
| **GOLD** | **OWASP Benchmark** | `EXECUTED` | 70 | 1.0000 `[0.9011, 1.0]` | 1.0000 `[0.9011, 1.0]` | **1.0000** `[0.9472, 1.0]` | `OwaspBenchmarkAdapter` |
| **SILVER** | **Juice Shop** | `NOT_EXECUTED` | 0 | N/A | N/A | N/A | Artifact not present in workspace |
| **SILVER** | **VAmPI** | `NOT_EXECUTED` | 0 | N/A | N/A | N/A | Artifact not present in workspace |
| **BRONZE** | **DVWA** | `EXECUTED` | 24 | 1.0000 `[0.7818, 1.0]` | 1.0000 `[0.7818, 1.0]` | **0.9167** `[0.7415, 0.9768]` | `DvwaManifestAdapter` |
| **BRONZE** | **WebGoat** | `NOT_EXECUTED` | 0 | N/A | N/A | N/A | Artifact not present in workspace |
| **BRONZE** | **NodeGoat** | `NOT_EXECUTED` | 0 | N/A | N/A | N/A | Artifact not present in workspace |

---

## Compliance with `INV-G5.2-03`
No mock metric dictionaries were generated for missing datasets (`Juice Shop`, `VAmPI`, `WebGoat`, `NodeGoat`). Their status is reported strictly as `NOT_EXECUTED`.
