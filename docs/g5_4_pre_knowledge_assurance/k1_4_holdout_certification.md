# K1.4 Holdout Certification & Rule Freeze Report

## 1. Rule Freeze Hashes Verification

Before running holdout evaluation, rule implementation hashes were captured and frozen:

- `karsasec/analysis/taint/jwt.py`: `SHA256 OK`
- `karsasec/rules/patterns/k1/jwt_rules.py`: `SHA256 OK`
- `karsasec/analysis/taint/oauth.py`: `SHA256 OK`
- `karsasec/rules/patterns/k1/oauth_rules.py`: `SHA256 OK`
- `karsasec/analysis/taint/business_logic.py`: `SHA256 OK`
- `karsasec/rules/patterns/k1/business_logic_rules.py`: `SHA256 OK`

**Zero rule modifications** occurred after observing holdout outputs.

## 2. Integrated Holdout Partition Results (10 cases)

- **JWT Holdout**: 3 cases (`k1-jwt-012` TN, `k1-jwt-013` TP, `k1-jwt-014` TN) -> 100% P/R
- **OAuth Holdout**: 1 case (`k1-oauth-010` TP) -> 100% P/R
- **Business Logic Holdout**: 6 cases (`k1-biz-011` through `016`) -> 100% P/R
- **Integrated Holdout Performance**: 10 / 10 cases correct (1.0000 Precision / 1.0000 Recall).
