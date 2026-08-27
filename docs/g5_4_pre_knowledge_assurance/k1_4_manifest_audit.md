# K1.4 Manifest / Rule / Property Consistency Audit Report

## 1. Machine-Verifiable 40-Case Mapping Audit Results

A total of 40 unique fixtures were audited across `manifest.json` and `holdout_manifest.json`:

| Knowledge Pack | Partition Breakdown | TP Cases | TN Cases | Total Cases | SHA256 Status | Rule ID Mapping Status |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **JWT** | 8 Dev / 3 Val / 3 Holdout | 8 | 6 | 14 | 100% Valid | 100% Mapped |
| **OAuth** | 6 Dev / 3 Val / 1 Holdout | 6 | 4 | 10 | 100% Valid | 100% Mapped |
| **Business Logic** | 6 Dev / 4 Val / 6 Holdout | 8 | 8 | 16 | 100% Valid | 100% Mapped |
| **Total Corpus** | **20 Dev / 10 Val / 10 Holdout** | **22** | **18** | **40** | **100% Valid** | **100% Mapped** |

## 2. Documented Discrepancy Audits

### OAuth Mapping Discrepancy Audit
- **Issue**: Historical query regarding `OAUTH_SCOPE_ESCALATION` mapping to `K1-OAUTH-006`.
- **Audit Findings**: `benchmarks/k1/holdout_manifest.json` defines `k1-oauth-010` with `expected_property: OAUTH_SCOPE_ESCALATION`. `oauth_rules.py` defines rule `K1-OAUTH-006` with `property: OAUTH_SCOPE_ESCALATION`. Mapping is 100% consistent and machine-verified.

### Business Logic Mapping Discrepancy Audit
- **Issue**: Historical query regarding property naming between manifest and reports.
- **Audit Findings**: All 8 Business Logic properties in `manifest.json` (`MISSING_AUTHZ`, `IDOR_HORIZONTAL`, `IDOR_VERTICAL`, `WORKFLOW_BYPASS`, `RACE_AUTHZ`, `QUANTITY_MANIPULATION`, `PRICE_MANIPULATION`, `INVARIANT_BYPASS`) map 1-to-1 to rules `K1-BIZ-001` through `K1-BIZ-008` in `k1_registry.py` and `business_logic_rules.py`.

Verified via `tests/benchmark/test_k1_4_manifest_audit.py`.
