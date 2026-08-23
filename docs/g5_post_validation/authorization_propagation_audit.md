# Phase 4 — Authorization Scope & Context Propagation Audit Report

## Audit Overview
Independent audit of D1 $\rightarrow$ D4 $\rightarrow$ D5 $\rightarrow$ D6 authorization reasoning in `karsasec/analysis/authz/engine.py` and `models.py`.

---

## 1. Scope Evaluation Results (`test_g5_authorization_scope.py`)

- **Matching Authorization Scope**:
  - `SubjectNode(roles=["ADMIN"])` + `ObjectNode(resource_type="ADMIN")` + `AuthorizationContext(authorization_scope="ADMIN")`
  - Result: **`ev is None` (Mitigated / SAFE)**

- **Permission Scope Mismatch**:
  - `SubjectNode(roles=["USER"])` + `ObjectNode(resource_type="ADMIN")` + `AuthorizationContext(authorization_scope="READ")`
  - Result: **`ev.vulnerability_type == AuthzVulnerabilityType.BFLA` (VULNERABLE / BFLA Violation)**

- **Endpoint / Resource Isolation**:
  - AuthzContext for `PUBLIC` scope applied to `ADMIN` object resource
  - Result: **`ev is not None` (Violation preserved; NOT SAFE)**

---

## 2. Invariant Verification (`INV-G5-AUTHORIZATION-PROPAGATION-01`)
Authorization context permissions attached to taint provenance are strictly checked against target resource scopes. Partial or mismatched authorization scopes do not grant universal safety.
