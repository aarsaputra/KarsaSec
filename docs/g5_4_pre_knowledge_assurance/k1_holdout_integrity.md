# K1 Holdout Integrity & Anti-Leakage Report (INV-G5.4-10)

## Holdout Locking Details
- **Holdout Manifest**: `benchmarks/k1/holdout_manifest.json`
- **Cryptographic Hash**: `benchmarks/k1/holdout_manifest.sha256`
- **Holdout Count**: 7 cases

---

## Anti-Leakage Safeguards
- Holdout partition locked prior to K1 rule optimization.
- Detector receives ONLY `{source_code, language, framework}` during holdout execution.
