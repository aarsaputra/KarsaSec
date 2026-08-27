# K1.6 Corpus & Baseline Snapshot Cryptographic Integrity Audit Report

## 1. Cryptographic Provenance Record (`INV-K1.6-01`, `INV-K1.6-03`, `INV-K1.6-11`)
Task **K1.6** verifies the cryptographic provenance and immutability of all 40 original K1 fixtures, manifest files, and the independent baseline findings snapshot.

- **Provenance Record File**: `benchmarks/k1/baseline/k1_4_provenance.json`
- **Schema Version**: `K1.6-1`
- **Baseline Version**: `K1.4`
- **Detector Revision**: Git commit `e44a3311681285265e1db87b1c3132bb`
- **Manifest SHA256**: Verified intact (0 mismatches)
- **Holdout Manifest SHA256**: Verified intact (0 mismatches)
- **Baseline Finding Snapshot**: `benchmarks/k1/baseline/k1_4_findings.json` (SHA256 locked, 40 cases)

## 2. Immutability Verification
Machine-verified via `tests/benchmark/test_k1_6_corpus_integrity.py`. All 40 fixture files exhibit byte-for-byte identity with 0 mismatches against the cryptographic provenance chain.
