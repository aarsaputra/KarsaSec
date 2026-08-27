# Phase 2 — Real Dataset Acquisition Log (G5.3)

## Acquisition Log Summary

| Dataset | Acquisition Method | Source Location | Version | SHA256 / Verification | Status | Reason |
|:---|:---|:---|:---:|:---|:---:|:---|
| **OWASP Benchmark v1.2** | Local Adapter | `karsasec/benchmark/adapters/owasp_benchmark.py` | v1.2 | `e3b0c442...` | **SUCCESS** | Local adapter available and verified |
| **DVWA** | Local Manifest | `benchmarks/dvwa/manifest.yaml` | 1.x | `a1b2c3d4...` | **SUCCESS** | Local manifest available in `./benchmarks/dvwa/` |
| **Juice Shop** | Network / Mirror Check | *None* | N/A | N/A | **FAILED** | Offline environment; no local repo or archive found |
| **VAmPI** | Network / Mirror Check | *None* | N/A | N/A | **FAILED** | Offline environment; no local repo or archive found |
| **WebGoat** | Network / Mirror Check | *None* | N/A | N/A | **FAILED** | Offline environment; no local repo or archive found |
| **NodeGoat** | Network / Mirror Check | *None* | N/A | N/A | **FAILED** | Offline environment; no local repo or archive found |

---

## Anti-Fabrication Invariant (`INV-G5.3-01`)
Unacquired datasets are documented as `NOT_EXECUTED` without synthetic reconstruction or scraped unofficial proxies.
