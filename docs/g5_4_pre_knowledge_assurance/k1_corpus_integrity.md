# K1 Corpus Provenance & Cryptographic Integrity Report (INV-G5.4.18 & INV-G5.4.19)

## 1. Corpus Partition Split (Exact 50 / 25 / 25)
- **Total Corpus Size**: 40 cases.
- **Development Partition (50%)**: 20 cases.
- **Validation Partition (25%)**: 10 cases.
- **Holdout Partition (25%)**: 10 cases.

---

## 2. Cryptographic Digest Audit
- **Full 64-Character Hexadecimal Hashes**: All SHA256 digests in `manifest.json`, `holdout_manifest.json`, and `oracle_manifest.json` are dynamically computed 64-character hex strings.
- **Zero Placeholder Hashes**: Confirmed zero abbreviated or empty-string (`e3b0c442...`) placeholder hashes.
