# K1.6 Determinism, Metadata Isolation & Cross-Pack Audit Report

## 1. Separation of Determinism Categories (`INV-K1.6-09`, `INV-K1.6-10`)
- **100-Pass Run Determinism ($D(\text{source}) == D(\text{source})$)**: Verified that running `analyze_k1` 100 consecutive times on a fixture yields 100% byte-for-byte identical SHA256 hashes over canonical JSON (`sort_keys=True`).
- **100-Pass Randomized Order Determinism ($D([\text{fixtures}]) == D([\text{shuffled\_fixtures}])$)**: Shuffling execution order across 100 passes with seeds `0..99` produced zero variance in per-fixture normalized finding SHA256 hashes.

## 2. Metadata Stripping & Cross-Pack Isolation (`INV-K1.6-07`, `INV-K1.6-08`)
- **Two-Way Full Label/Comment Stripping**: Stripping comments, randomizing filenames, removing case IDs/metadata across both positive and negative fixtures produced 0 alteration in detector finding sets (`normalize(D(original)) == normalize(D(stripped))`).
- **Cross-Pack Isolation**: Zero cross-pack finding contamination detected across JWT, OAuth, and Business Logic domains.

Verified via `tests/benchmark/test_k1_6_determinism.py` and `test_k1_6_label_leakage.py`.
