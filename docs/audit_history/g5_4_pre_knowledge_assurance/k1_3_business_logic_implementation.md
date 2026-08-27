# K1.3 Business Logic Implementation Architecture Report

## 1. Overview
The Business Logic Knowledge Pack (`karsasec/analysis/taint/business_logic.py`, `karsasec/rules/patterns/k1/business_logic_rules.py`) implements AST-based static semantic analysis for 8 business logic security properties.

## 2. Invariant & Production Scope Compliance
- **INV-K1.3-01 (Scope Isolation)**: Changes are strictly confined to `business_logic.py` and `business_logic_rules.py`. `jwt.py` and `oauth.py` remain 100% untouched.
- **Oracle Separation**: Zero label leakage into detector execution (`{source_code, language, framework}`).
- **Two-Stage Oracle**: `analyze_fixture(source_code)` evaluates AST independently of ground truth labels.
- **Safe Controls**: Verified secure counterparts for every business logic vulnerability family.
- **Semantic Ground Truth**: All 16 fixtures contain AST-realizable control-flow/data-flow constructs without naive string matching.

## 3. Vulnerability Properties Covered
1. `MISSING_AUTHZ`: Sensitive/destructive endpoint operations without authorization decorators or permission checks (`K1-BIZ-001`).
2. `IDOR_HORIZONTAL`: Resource query/lookup directly driven by parameter without ownership constraint (`K1-BIZ-002`).
3. `IDOR_VERTICAL`: Role mutation or privilege escalation without super admin verification (`K1-BIZ-003`).
4. `WORKFLOW_BYPASS`: Order fulfillment or state mutation without workflow state precondition checks (`K1-BIZ-004`).
5. `RACE_AUTHZ`: Financial or balance mutation performed without pessimistic row-level locking (`K1-BIZ-005`).
6. `QUANTITY_MANIPULATION`: Order quantity accepted without non-positive numeric validation (`K1-BIZ-006`).
7. `PRICE_MANIPULATION`: Unit price accepted directly from client request body instead of product master (`K1-BIZ-007`).
8. `INVARIANT_BYPASS`: Discount application lacking single-use invariant validation (`K1-BIZ-008`).
