# Phase 3 — Sanitizer Semantic Audit & Cross-Property Report

## Audit Overview
Independent adversarial audit of `SanitizerResolver` and `SanitizerRegistry` in `karsasec/analysis/taint/sanitizers.py`.

---

## 1. Property-Specific Safety Validation

- **HTML Escaping (`html.escape`)**:
  - Target: `CROSS_SITE_SCRIPTING` (HTML Body/Attribute) $\rightarrow$ **`is_verified_safe = True`**
  - Target: `SQL_INJECTION` $\rightarrow$ **`is_verified_safe = False`** (`NOT SAFE`)
  - Target: `JAVASCRIPT_CONTEXT` $\rightarrow$ **`is_verified_safe = False`** (`NOT SAFE`)

- **Prepared Statements (`prepareStatement`)**:
  - Target: `SQL_INJECTION` / `SQL_QUERY` $\rightarrow$ **`is_verified_safe = True`**
  - Target: `CROSS_SITE_SCRIPTING` $\rightarrow$ **`is_verified_safe = False`** (`NOT SAFE`)

- **Primitive Type Casting (`int(user_input)`)**:
  - Target: `SQL_INJECTION` $\rightarrow$ **`is_verified_safe = True`**
  - Target: `CROSS_SITE_SCRIPTING` $\rightarrow$ **`is_verified_safe = False`** (`NOT SAFE`)

---

## 2. Detection of Deceptive & Misleading Routines

- **Noop / Fake Sanitizer (`def fake_sanitize(x): return x`)**:
  - Resolved as `SAN_INEFFECTIVE` $\rightarrow$ **`is_verified_safe = False`**
- **Logging Wrapper (`def sanitize_sql(x): log(x); return x`)**:
  - Unproven wrapper $\rightarrow$ **Default `None` (`UNKNOWN`)**

---

## 3. Epistemic Safety
Functions are evaluated based on transformation semantics rather than name matching alone. Misleading function names do not inflate safety scores.
