# K1 Holdout Generalization & Anti-Leakage Report (INV-G5.4.17)

## 1. Textual & AST Duplicate Analysis
- **Textual Duplicates**: `tests/benchmark/test_g5_k1_holdout_leakage.py` verified **0 textual SHA256 collisions** between Development and Holdout sets (`dev_hashes ∩ holdout_hashes = ∅`).
- **Syntactic & Structural Diversity**: Holdout fixtures feature unique function names, control-flow shapes, helper abstractions, and API invocation patterns to test semantic generalization.

---

## 2. Holdout Partition Locking
- **Holdout Count**: 10 cases (3 JWT, 1 OAuth, 6 Business Logic).
- **Holdout Manifest Digest**: Computed dynamically and saved to `benchmarks/k1/holdout_manifest.sha256`.
