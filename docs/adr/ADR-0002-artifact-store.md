# ADR-0002: Centralized Immutable Artifact Store Architecture

* **Status:** Accepted
* **Date:** 2026-08-05
* **Authors:** KarsaSec Core Platform Architecture Team

## Context

Without a centralized data store, passes exchange state by directly mutating shared objects, leading to subtle race conditions, side-effects, and untracked memory consumption.

## Decision

We establish the **Centralized Immutable Artifact Store (`karsasec/runtime/artifact_store.py`)**. The `ArtifactStore` acts as a read/write repository for intermediate analysis results (`AST`, `HIR`, `MIR`, `LIR`, `CFG`, `CallGraph`, `Dataflow`, `Evidence`). Passes retrieve inputs from and publish outputs to the store.

## Consequences

### Positive
- Strict immutability and ownership rules per artifact.
- Eliminates cross-module state mutation and unexpected side-effects.
- Enables single-build, multi-consumer caching strategies.

### Negative
- Requires explicit serialization/dataclass structures for artifact entries.
