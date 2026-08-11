# ADR-0006: Flask Semantic Evidence Correlation & Provenance Architecture

* **Status**: Accepted
* **Date**: 2026-08-09
* **Authors**: Principal Software Architect & Senior Security Engineer
* **Decider**: Architecture Steering Committee

---

## Context and Problem Statement

Following Sprint E10-3E (Semantic Evidence Expansion), KarsaSec added deterministic evidence attributes to ISR v1.1 and the `FrameworkSemanticGraph`. However, before introducing advanced multi-node security rules (Tier-C), the engine required explicit evidence provenance metadata, guaranteed graph traceability, deterministic conflict resolution, and canonical value normalization.

Without explicit provenance and conflict resolution, complex multi-node rules risk false positives due to silent default selection or evidence leakage across semantic nodes.

---

## Decision Drivers

1. **Evidence-First Architecture**: Every semantic attribute MUST trace back to explicit source evidence with deterministic confidence classification (`HIGH`, `MEDIUM`, `UNKNOWN`).
2. **Conflict Safety (`CONFLICT -> UNKNOWN`)**: Contradictory evidence (e.g. `@sensitive` + `@public` on one route) MUST resolve to `"UNKNOWN"` to guarantee missing-evidence safety and zero false positive findings.
3. **Graph-Only Rule Evaluation**: Security rules consume ONLY `FrameworkSemanticGraph` attributes and relationships, keeping evaluation free of ASTs, network, filesystem, or dynamic imports.
4. **Order Invariance**: 10x repeated execution with shuffled nodes, edges, rules, and evidence MUST produce 100% identical SHA-256 finding fingerprints.

---

## Decision Outcome

### 1. EvidenceProvenance Data Structure
Added `EvidenceProvenance` in `karsasec.framework.origin`:
```python
@dataclass(frozen=True)
class EvidenceProvenance:
    value: Any
    source_kind: str   # explicit_decorator, explicit_assignment, explicit_env, derived_relation, unknown
    confidence: str    # HIGH, MEDIUM, UNKNOWN
    file_path: str = ""
    line: int = 1
    origin_id: str = ""
```

Confidence is strictly mapped deterministically based on evidence `source_kind`:
- `explicit_decorator`, `explicit_assignment`, `explicit_env` $\rightarrow$ `HIGH`
- `derived_relation` $\rightarrow$ `MEDIUM`
- `unknown` $\rightarrow$ `UNKNOWN`

### 2. Graph Traceability
ISR definitions (`RouteDefinition`, `AuthDefinition`, `ConfigDefinition`) carry `provenance_map: dict[str, EvidenceProvenance]`. `FrameworkNodeFactory` serializes this metadata into `FrameworkSemanticNode.attributes["_provenance"]`.

### 3. Conflict Resolution Policy (`CONFLICT -> UNKNOWN`)
If contradictory explicit evidence is detected during normalization/extraction:
- Route sensitivity/exposure: `"UNKNOWN"`
- Config environment: `"UNKNOWN"`

When an attribute value resolves to `"UNKNOWN"`, rule predicates fail (`predicate == False`), generating 0 findings.

### 4. Canonical Normalization
Environment strings (`"prod"`, `"PROD"`, `"production"`) map to `"PRODUCTION"`. Normalization occurs ONLY from explicit AST settings, never inferred from file or directory names.

### 5. Tier-C Rule Architecture
Introduced multi-node graph security rules evaluating node attributes and relationships:
- `KS-FLASK-AUTH-0004`: Sensitive Endpoint Protected by Weak Authentication (`HIGH` sensitivity route protected by `AUTH`/`MIDDLEWARE` with `auth_strength == WEAK`).
- `KS-FLASK-CONF-0004`: Hardcoded Secret Key Assignment (`SECRET_KEY` with `source_kind == literal` and `provenance_type == assignment`).
- `KS-FLASK-JWT-0002`: Insecure JWT Signing Policy Violation (`auth_type == JWT` with explicitly configured weak signing algorithm).

---

## Consequences

* **Positive**: Tier-C rules operate on verified multi-node graph evidence with zero false positives from ambiguous or conflicting code.
* **Positive**: Full auditability—every finding explains the source file, line, and origin of its evidence.
* **Negative**: Requires small overhead to store `_provenance` in node attributes (benchmarks confirm sub-millisecond graph evaluation).
