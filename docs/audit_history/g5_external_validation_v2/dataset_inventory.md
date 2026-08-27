# Phase 1 — Dataset Discovery & Inventory Report (G5.3)

## Dataset Inventory Summary

| Dataset | Version | Artifact Path / Provenance | Adapter | Ground Truth Source | Execution Status | Status Rationale |
|:---|:---:|:---|:---:|:---|:---:|:---|
| **OWASP Benchmark** | v1.2 | `karsasec/benchmark/adapters/owasp_benchmark.py` | `OwaspBenchmarkAdapter` | OWASP Official CSV Manifest | **EXECUTED** | Available (70-case subset) |
| **DVWA (Damn Vulnerable Web App)** | 1.x | `benchmarks/dvwa/manifest.yaml` | `DvwaManifestAdapter` | `manifest.yaml` verified ground truth | **EXECUTED** | Available in `./benchmarks/dvwa/` |
| **OWASP Juice Shop** | v14.x | *None* | *None* | *None* | **NOT_EXECUTED** | Artifact not present in workspace environment |
| **VAmPI REST API** | v0.1 | *None* | *None* | *None* | **NOT_EXECUTED** | Artifact not present in workspace environment |
| **WebGoat (Java)** | v8.x | *None* | *None* | *None* | **NOT_EXECUTED** | Artifact not present in workspace environment |
| **NodeGoat (Node.js)** | v1.x | *None* | *None* | *None* | **NOT_EXECUTED** | Artifact not present in workspace environment |

---

## Provenance Integrity Invariant (`INV-G5.3-01`)
In accordance with `INV-G5.3-01`, missing dataset artifacts (`Juice Shop`, `VAmPI`, `WebGoat`, `NodeGoat`) are reported strictly as `NOT_EXECUTED`. Zero synthetic metrics or mock dictionary structures are substituted.
