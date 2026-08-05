# ADR-0003: Multi-Layered IR Architecture (HIR -> MIR -> LIR)

* **Status:** Accepted
* **Date:** 2026-08-05
* **Authors:** KarsaSec Core Platform Architecture Team

## Context

Directly matching security rules against language-specific AST structures creates code duplication and forces rules to understand syntax quirks across Python, JavaScript, Go, and PHP.

## Decision

We adopt a 3-layer Intermediate Representation:
1. **High-Level IR (HIR)**: Retains language-specific syntax structures.
2. **Medium-Level IR (MIR)**: Unified semantic program model (`MIRConditional`, `MIRAssign`, `MIRCall`).
3. **Low-Level Analysis IR (LIR)**: Flow analysis primitives (`LIRSource`, `LIRSink`, `LIRSanitizer`).

Security rules operate exclusively on MIR and LIR abstractions.

## Consequences

### Positive
- Unified rule matching regardless of target language.
- New programming languages only require building an HIR->MIR builder pass.

### Negative
- Initial translation pass cost per file (~3-5 ms).
