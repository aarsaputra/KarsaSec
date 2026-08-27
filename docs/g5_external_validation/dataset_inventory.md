# Phase 2 — Dataset Discovery & Inventory Report

## Inventory Summary

| Dataset | Quality Tier | Artifact Path / Provenance | Adapter | Ground Truth Source | Executable Status | Status Rationale |
|:---|:---:|:---|:---:|:---|:---:|:---|
| **OWASP Benchmark v1.2** | GOLD | `karsasec/benchmark/adapters/owasp_benchmark.py` | `OwaspBenchmarkAdapter` | OWASP Official CSV Manifest | **EXECUTABLE** | Available (70-case subset) |
| **DVWA (Damn Vulnerable Web App)** | BRONZE | `benchmarks/dvwa/manifest.yaml` | `DvwaManifestAdapter` | `manifest.yaml` ground truth | **EXECUTABLE** | Available in `./benchmarks/dvwa/` |
| **OWASP Juice Shop** | SILVER | *None* | *None* | *None* | **NOT_EXECUTED** | Artifact not present in workspace environment |
| **VAmPI REST API** | SILVER | *None* | *None* | *None* | **NOT_EXECUTED** | Artifact not present in workspace environment |
| **WebGoat (Java)** | BRONZE | *None* | *None* | *None* | **NOT_EXECUTED** | Artifact not present in workspace environment |
| **NodeGoat (Node.js)** | BRONZE | *None* | *None* | *None* | **NOT_EXECUTED** | Artifact not present in workspace environment |

---

## Metric Integrity Invariant (`INV-G5.2-03`)
In accordance with `INV-G5.2-03`, unexecuted datasets (`Juice Shop`, `VAmPI`, `WebGoat`, `NodeGoat`) are reported strictly as `NOT_EXECUTED`. Zero synthetic metrics or mock dictionaries are substituted.
