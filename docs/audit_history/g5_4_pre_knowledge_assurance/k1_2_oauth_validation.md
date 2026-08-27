# K1.2 OAuth Validation Partition Report

## 1. Development & Validation Partition Performance

### Development Partition (6 cases)
- **TP Detected**: 3 / 3 (100% Recall)
- **TN Protected**: 3 / 3 (100% Precision)
- **Cases Tested**: `k1-oauth-001` through `k1-oauth-006`

### Validation Partition (3 cases)
- **TP Detected**: 2 / 2 (100% Recall)
- **TN Protected**: 1 / 1 (100% Precision)
- **Cases Tested**: `k1-oauth-007` (`OAUTH_CODE_REUSE`), `k1-oauth-008` (`OAUTH_TOKEN_LEAKAGE`), `k1-oauth-009` (`OAUTH_TOKEN_LEAKAGE` Safe Control)

## 2. Generalization Verdict
Rules calibrated on the 6 Development cases generalized perfectly across all 3 Validation cases with 0 false positives and 0 false negatives.
