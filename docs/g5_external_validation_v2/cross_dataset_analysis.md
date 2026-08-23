# Phase 8 — Cross-Dataset Differential Analysis Report (G5.3)

## Cross-Dataset Execution Matrix

| Tier | Dataset | Status | N | Strict Precision (95% CI) | Strict Recall (95% CI) | FPR | Specificity | EDC (95% CI) | Rationale / Provenance |
|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **GOLD** | **OWASP Benchmark** | `EXECUTED` | 70 | 1.0000 `[0.9011, 1.0]` | 1.0000 `[0.9011, 1.0]` | 0.0000 | 1.0000 | **1.0000** `[0.9472, 1.0]` | `OwaspBenchmarkAdapter` |
| **SILVER** | **Juice Shop** | `NOT_EXECUTED` | 0 | N/A | N/A | N/A | N/A | N/A | Artifact not present |
| **SILVER** | **VAmPI** | `NOT_EXECUTED` | 0 | N/A | N/A | N/A | N/A | N/A | Artifact not present |
| **BRONZE** | **DVWA** | `EXECUTED` | 24 | 1.0000 `[0.7818, 1.0]` | 1.0000 `[0.7818, 1.0]` | 0.2000 | 0.8000 | **0.9167** `[0.7415, 0.9768]` | `DvwaManifestAdapter` |
| **BRONZE** | **WebGoat** | `NOT_EXECUTED` | 0 | N/A | N/A | N/A | N/A | N/A | Artifact not present |
| **BRONZE** | **NodeGoat** | `NOT_EXECUTED` | 0 | N/A | N/A | N/A | N/A | N/A | Artifact not present |

---

## Metric Integrity Invariant (`INV-G5.3-01 & INV-G5.3-08`)
Missing datasets are recorded strictly as `NOT_EXECUTED`. Zero synthetic metrics or mock dictionary structures were substituted.
