# ADR-0004: Extensible Plugin SDK & Capability Negotiation

* **Status:** Accepted
* **Date:** 2026-08-05
* **Authors:** KarsaSec Core Platform Architecture Team

## Context

Third-party parsers, custom rule packs, and external reporters need to integrate cleanly without mutating core platform files.

## Decision

We introduce the **Plugin SDK & Capability Negotiator (`karsasec/sdk/`)**. Third-party plugins declare a `PluginManifest` with explicitly versioned Analysis API requirements (`v1`, `v2`, `v3`). The `CapabilityNegotiator` validates manifest compatibility before registering plugins into the engine.

## Consequences

### Positive
- Strict isolation of third-party plugins.
- Prevents runtime crashes from incompatible extension versions.

### Negative
- Plugin authors must adhere to versioned API manifests.
