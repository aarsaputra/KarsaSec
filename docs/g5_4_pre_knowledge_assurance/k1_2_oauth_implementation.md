# K1.2 OAuth Implementation Architecture Report

## 1. Overview
The OAuth Knowledge Pack (`karsasec/analysis/taint/oauth.py`, `karsasec/rules/patterns/k1/oauth_rules.py`) implements AST-based static analysis for OAuth 2.0 / 2.1 authorization flows.

## 2. Invariant Compliance
- **INV-K1.2-01 (Scope Isolation)**: Changes are strictly limited to `oauth.py` and `oauth_rules.py`. JWT and Business Logic modules remain 100% untouched.
- **INV-K1.2-02 (Oracle Separation)**: Zero label leakage into detector execution (`{source_code, language, framework}`).
- **INV-K1.2-03 (Two-Stage Oracle)**: `analyze_fixture(source_code)` evaluates AST independently of ground truth labels.
- **INV-K1.2-04 (Safe Controls)**: Verified secure counterparts for every OAuth vulnerability family.
- **INV-K1.2-05 (Semantic Ground Truth)**: All fixtures contain AST-realizable control-flow/data-flow constructs.

## 3. Vulnerability Properties Covered
1. `OAUTH_REDIRECT_URI`: Insecure/unvalidated redirect URI in authorization requests.
2. `OAUTH_MISSING_STATE`: Missing CSRF state parameter in authorization callbacks.
3. `OAUTH_MISSING_PKCE`: Missing Proof Key for Code Exchange (`code_challenge` / `S256`).
4. `OAUTH_CODE_REUSE`: Authorization code reuse / missing single-use invalidation logic.
5. `OAUTH_TOKEN_LEAKAGE`: Unsafe exposure of access tokens in URL parameters.
6. `OAUTH_SCOPE_ESCALATION`: Requested/granted scope exceeding authorized boundaries without validation.
