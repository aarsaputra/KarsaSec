# Phase 0 — Architecture Forensics & Root Cause Analysis Report

## Executive Summary

Pursuant to the Senior Security Architect Directive, this document establishes the formal root-cause analysis for the three primary failure modes identified during the Gate 5 OWASP Benchmark baseline and mutation evaluation:
1. `FN_FRAMEWORK` (Unresolved HTTP Request Wrappers)
2. `UNRESOLVED_WRAPPER` (Unresolved Custom Sanitizers & Security Wrappers)
3. `MUT-AUTH-001` (Surviving Authorization Mutation & Unpropagated Authorization Context)

---

## 1. Failure Mode 1: `FN_FRAMEWORK` (Unresolved HTTP Request Wrappers)

### Overview
- **Failure**: HTTP request wrapper methods (e.g., `request.getParameter(...)`, `request.args.get(...)`, `wrapper.getParameter(...)`, `customRequest.getInput(...)`) are not resolved as user-controlled taint sources when encapsulated within custom or framework wrapper objects.
- **Execution Path**:
  ```text
  AST Parsing
     ↓
  SourceRegistry.is_source() / match_source() [karsasec/analysis/taint/sources.py]
     ↓
  Taint Engine Pass [karsasec/analysis/taint/engine.py]
     ↓
  D1 Invariants Engine [karsasec/analysis/invariants/engine.py] (Fails to create Source Taint Node)
     ↓
  D4 Correlation Engine (No source node in causal graph)
     ↓
  D5 / D6 Decision (Yields UNKNOWN / FN_EPISTEMIC)
  ```
- **Responsible Layer**: Source Resolution & Framework Abstraction Layer (`karsasec/analysis/taint/sources.py`, `karsasec/analysis/framework/`).
- **Root Cause**: `SourceRegistry` uses a static dictionary of verbatim text patterns per language (e.g., `"request.args"`). It lacks a generalized `SourceResolver` and `FrameworkAdapter` protocol capable of resolving method delegation, HTTP request interfaces (`getParameter`, `getHeader`, `get_input`, `body`), or interprocedural wrapper delegation.
- **Why Current Architecture Cannot Resolve It**: Calling `wrapper.getParameter("id")` or `customRequest.getInput()` fails string pattern matching because `wrapper.getParameter` is not present in the hardcoded string list, and delegate relationships between `Wrapper` and `HttpRequest` are not modeled.
- **Proposed Generalized Solution**:
  - Implement `SourceSemantics` dataclass tracking `source_origin`, `wrapper_chain`, `framework`, `function`, `call_site`, `confidence`.
  - Build `SourceResolver` supporting direct sources, wrapper sources, delegated sources, and framework sources across Java Servlet, Spring, Python Flask, Django, and Node Express.
  - Epistemic Rule: If an arbitrary wrapper cannot be proven user-controlled, return `UNKNOWN` (never force `SAFE` or `VULNERABLE`).
- **False-Positive Risks**: Treating internal non-user getters (e.g., `config.get()`) as sources. Mitigated by signature matching against HTTP/Request context interfaces.
- **False-Negative Risks**: Deeply nested reflective invocation chains. Mitigated by recursive wrapper unwrapping.
- **Affected Invariants**: `INV-D1-REACHABILITY-01`, `INV-D4-PROVENANCE-01`.
- **Affected Tests**: `tests/benchmark/test_gate_5_infrastructure.py`, `tests/decision/test_security_decision_engine.py`.

---

## 2. Failure Mode 2: `UNRESOLVED_WRAPPER` (Unresolved Custom Sanitizers)

### Overview
- **Failure**: Custom sanitizers or security wrappers (e.g., `def sanitize(val): return escape_sql(val)`) default to `UNKNOWN` or are ignored because function-level sanitization wrappers are not dynamically recognized or categorized by security property.
- **Execution Path**:
  ```text
  AST Parsing
     ↓
  SanitizerRegistry.is_sanitizer() [karsasec/analysis/taint/sanitizers.py]
     ↓
  Taint Propagator [karsasec/analysis/taint/propagator.py]
     ↓
  D5 Property Proof Engine [karsasec/analysis/proof/engine.py]
     ↓
  D6 Security Decision Engine (Yields UNKNOWN)
  ```
- **Responsible Layer**: Sanitizer Semantics & Transformation Model (`karsasec/analysis/taint/sanitizers.py`, `karsasec/analysis/proof/`).
- **Root Cause**: `SanitizerRegistry` performs naive substring matching against predefined builtin function names (`htmlspecialchars`, `PreparedStatement`). It cannot inspect function bodies, interprocedural sanitizer wrappers, or verify whether a sanitizer validly mitigates a specific `SecurityProperty` (e.g., `SQL_INJECTION` vs `XSS`).
- **Why Current Architecture Cannot Resolve It**: A wrapper function `custom_sanitize(input)` is absent from `DEFAULT_CONTEXT_SANITIZERS`. Without a structured `SanitizerSemantics` model tracking `input_provenance`, `output_provenance`, `security_property`, `transformation_type`, and `confidence`, D5 proof defaults to `UNKNOWN`.
- **Proposed Generalized Solution**:
  - Implement `SanitizerSemantics` model (`sanitizer_id`, `input_provenance`, `output_provenance`, `security_property`, `transformation_type`, `confidence`, `evidence`).
  - Build `SanitizerResolver` distinguishing 4 explicit states:
    1. Verified Safe Sanitizer -> `SAFE` contribution
    2. Verified Unsafe Transformation -> `VULNERABLE` contribution
    3. Unknown Wrapper -> `UNKNOWN`
    4. Contradictory Evidence (sanitizer present alongside raw unauthenticated sink) -> `CONFLICT`
  - Strict Rule: Do NOT trust function names like `sanitize()` blindly; require explicit semantic rules or verified dataflow transformations.
- **False-Positive Risks**: Treating an ineffective sanitizer (e.g., `html.escape`) as safe for `SQL_INJECTION`. Prevented by strict `SecurityProperty` context matching.
- **False-Negative Risks**: Classifying safe custom sanitizers as `UNKNOWN`. This is epistemically safe (preserves `UNKNOWN` over false confidence).
- **Affected Invariants**: `INV-D5-PROPERTY-PROOF-01`, `INV-D6-RISK-EP-01`.
- **Affected Tests**: `tests/decision/test_post_d6_architectural_audit.py`, `tests/decision/test_security_decision_engine.py`.

---

## 3. Failure Mode 3: `MUT-AUTH-001` (Unpropagated Authorization Context)

### Overview
- **Failure**: When a semantic mutation adds an authorization check `@require_permission("ADMIN")` or `check_permission()`, the decision engine verdict remained `VULNERABLE` instead of transitioning to `SAFE` or `UNKNOWN`.
- **Execution Path**:
  ```text
  AST Parsing (Decorator / Authorization Check)
     ↓
  Batch B1 Authz Engine [karsasec/analysis/authz/engine.py] (Generates local AuthzEvidence)
     ↓
  D1 Invariants Engine (Does NOT attach authorization context to taint nodes)
     ↓
  D4 Correlation Engine (No AUTHORIZATION_CONTEXT evidence edges in causal graph)
     ↓
  D5 Proof Engine (Ignores authorization mitigation)
     ↓
  D6 Decision Engine (_compute_business_risk calculates risk without authorization reduction)
     ↓
  Engine Output: VULNERABLE (Mutant SURVIVED)
  ```
- **Responsible Layer**: Authorization Evidence Model & Cross-Batch Context Propagation (`karsasec/analysis/authz/`, `karsasec/analysis/correlation/`, `karsasec/analysis/decision/`).
- **Root Cause**: Authorization checks evaluated in Batch B1 produce `AuthzEvidence` for IDOR/BOLA, but decoration/function-level authorization evidence (`AuthorizationContext`) is NOT attached to taint nodes in D1 or propagated through D4 correlation graphs into D5 proof and D6 decision engines.
- **Why Current Architecture Cannot Resolve It**: D4 correlation engines model `CausalEvidenceType` (`DATA_DEPENDENCY`, `CONTROL_DEPENDENCY`, `PRIVILEGE_TRANSITION`, etc.) but lack explicit `AUTHORIZATION_CONTEXT` evidence edges. D6 `_compute_business_risk` calculates risk purely based on vulnerability reachability without checking if authorization context mitigates the reachability or exploitability.
- **Proposed Generalized Solution**:
  - Implement generalized `AuthorizationContext` model (`actor`, `principal`, `required_permission`, `granted_permission`, `authorization_source`, `authorization_scope`, `resource_scope`, `enforcement_point`, `confidence`, `provenance`).
  - Attach `AuthorizationContext` evidence to AST function definitions, call sites, and decorators during D1 pass.
  - Propagate `AuthorizationContext` through D4 correlation graph as explicit security evidence.
  - In D5 proof and D6 decision engines, verify authorization scope against resource scope:
    - If fully covered -> `SAFE` contribution
    - If scope mismatched -> `UNKNOWN` or `VULNERABLE`
    - If contradictory -> `CONFLICT`
  - Invariant: Authorization evidence MUST NEVER be silently discarded between D1 -> D4 -> D5 -> D6.
- **False-Positive Risks**: Over-trusting authorization checks that verify the wrong permission or scope. Prevented by matching `required_permission` against endpoint/resource scope.
- **False-Negative Risks**: Dropping valid authorization checks due to missing decorator metadata. Handled by fallback to `UNKNOWN`.
- **Affected Invariants**: `INV-D4-CAUSALITY-01`, `INV-D6-RISK-EP-01`, `INV-G5-AUTHORIZATION-PROPAGATION-01`.
- **Affected Tests**: `tests/benchmark/test_gate_5_infrastructure.py`, `tests/decision/test_post_d6_architectural_audit.py`.

---

## Summary Matrix

| Failure Mode | Layer | Root Cause | Generalized Fix | Epistemic Safeguard |
|:---|:---|:---|:---|:---|
| `FN_FRAMEWORK` | Taint / Source Resolution | Hardcoded string matching; missing `SourceResolver` and `FrameworkAdapter` | Generalized `SourceResolver` & `SourceSemantics` with wrapper delegation | Unproven wrapper yields `UNKNOWN` |
| `UNRESOLVED_WRAPPER` | Taint / Sanitizer | Substring matching on builtins; missing property-specific `SanitizerSemantics` | `SanitizerSemantics` model matching `SecurityProperty` and verified transformations | Unproven sanitizer yields `UNKNOWN`; contradiction yields `CONFLICT` |
| `MUT-AUTH-001` | Authz / Correlation / Decision | `AuthorizationContext` not attached to D1 nodes or propagated through D4->D5->D6 | `AuthorizationContext` propagation through D1->D4->D5->D6 pipeline | Scope mismatch yields `UNKNOWN`/`VULNERABLE`; contradiction yields `CONFLICT` |
