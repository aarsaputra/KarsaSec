# K1.5 Determinism & Metadata Isolation Report

## 1. Evaluation Summary
- **100-Pass Execution Determinism**: Verified that running `analyze_k1` 100 consecutive times on adversarial fixtures yields byte-for-byte / structurally identical finding outputs.
- **Label Leakage Resilience**: Injecting `# expected_property: SAFE` or `# expected_status: TRUE_NEGATIVE` comment metadata into vulnerable code produced zero change in findings.
- **Adversarial Cross-Pack Isolation**: Zero cross-pack finding contamination detected across all 20 positive adversarial cases (`INV-K1.5-06`).

Verified via `tests/benchmark/test_k1_5_determinism.py`, `test_k1_5_no_label_leakage.py`, and `test_k1_5_cross_pack_isolation.py`.
