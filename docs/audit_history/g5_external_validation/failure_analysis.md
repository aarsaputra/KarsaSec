# Phase 10 — Failure Analysis Report (G5.2 External Validation)

## Summary of Evaluated Failures
All false positives and false negatives on executed datasets (`OWASP Benchmark` and `DVWA`) have been classified by root cause.

---

## 1. Failure Records Table

| Dataset | Case ID | CWE | Predicted | Ground Truth | Root Cause Category | Analysis & Remediation Candidate |
|:---|:---|:---:|:---:|:---:|:---|:---|
| **DVWA** | `dvwa-exec-impossible-001` | CWE-78 | `VULNERABLE` | `SAFE` | `sanitizer_proof` | Regex IP whitelist validation before `shell_exec`. Requires regex constraint solver integration. |
| **DVWA** | `dvwa-exec-impossible-002` | CWE-78 | `VULNERABLE` | `SAFE` | `sanitizer_proof` | Unix variant of regex whitelist guard before `shell_exec`. |

---

## 2. Benchmark Remediation Invariant (`INV-G5.2-08`)
In accordance with `INV-G5.2-08`, zero detector files in `karsasec/analysis/` were patched during this certification run. The identified failures are recorded as remediation candidates for future core solver engineering tasks.
