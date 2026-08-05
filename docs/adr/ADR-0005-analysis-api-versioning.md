# ADR-0005: Versioned Analysis API Lifecycle Governance

* **Status:** Accepted
* **Date:** 2026-08-05
* **Authors:** KarsaSec Core Platform Architecture Team

## Context

As static analysis capabilities evolve, breaking changes in core APIs must not destabilize existing enterprise rules or community plugins.

## Decision

We establish an explicit API Lifecycle governance model:
`Experimental -> Beta -> Stable -> Deprecated -> Removed`

Internal interfaces, rule schemas, finding formats, and SARIF export definitions adhere strictly to semantic versioning. Deprecated APIs maintain backward compatibility for at least one major release cycle.

## Consequences

### Positive
- Production-grade predictability for DevSecOps integration.
- Clear deprecation path without unexpected breaking changes.

### Negative
- Requires maintaining compatibility shims during transition phases.
