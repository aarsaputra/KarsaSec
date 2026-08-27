# K1.2 OAuth Holdout Blind Evaluation Report

## 1. Holdout Blind Evaluation Execution
- **Holdout Case**: `k1-oauth-010` (`OAUTH_SCOPE_ESCALATION`)
- **Expected Status**: `TRUE_POSITIVE`
- **Result**: `TRUE_POSITIVE` (Detected rule `K1-OAUTH-006` on line 1)

## 2. Invariant Audit
- **Holdout Independence**: Zero rule modifications were performed after accessing the holdout evaluation fixture.
- **SHA256 Integrity**: `4650e0190a6a93fc7e999f6d5b9832623fec7c6c401d54975c263eff53bef716` verified.
- **Textual & Fingerprint Non-Overlap**: 0 textual or AST fingerprint collisions with development set.
