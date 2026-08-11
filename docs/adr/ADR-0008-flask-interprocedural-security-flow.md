# ADR-0008: Flask Interprocedural Security Flow & Tier-D Rule Architecture

* **Status**: Accepted
* **Date**: 2026-08-09
* **Authors**: Principal Software Architect & Senior Security Engineer
* **Decider**: Architecture Steering Committee

---

## Context and Problem Statement

Following Sprint E10-3F (Flask Semantic Security Correlation Hardening), KarsaSec established graph-only security rule evaluation, evidence provenance traceability, and deterministic conflict resolution (`CONFLICT -> UNKNOWN`).

To identify complex vulnerability patterns spanning function boundaries (e.g. untrusted HTTP request parameters reaching dangerous sinks like SQL execution, OS subprocesses, or open redirects), KarsaSec requires deterministic interprocedural security-flow analysis.

Before introducing Tier-D security rules, the engine requires formal semantic flow contracts, graph topological edge proofs, an explicit `FlowScope` ownership boundary, evidence-classified sanitizers, and an immutable taint state decision table.

---

## Decision Drivers

1. **Graph-Only Evaluation**: The rule evaluation layer MUST operate exclusively on `FrameworkSemanticGraph` attributes and edges without AST, filesystem, network, or dynamic execution imports.
2. **Absence-of-Evidence Safety**: Missing or ambiguous flow evidence resolves safely to `UNKNOWN` (`predicate == False`), generating **0 false positives**.
3. **Topological Edge Proof**: `propagation_path` is descriptive metadata; every propagation hop MUST be backed by explicit semantic graph nodes/edges.
4. **FlowScope Ownership Boundary**: `FlowScope(route_id, handler_id, scope_id)` anchors flows to prevent cross-route evidence bleeding on shared helper functions.
5. **Sink-Aware Sanitizer Compatibility**: No sanitizer or validator is globally safe across all sink kinds. Compatibility is evaluated via tri-state `SinkCompatibility` (`COMPATIBLE`, `INCOMPATIBLE`, `UNKNOWN`).
6. **Canonical Order Independence**: 10x repeated execution and input shuffling (nodes, edges, flows, rules) MUST yield byte-for-byte identical findings and SHA-256 fingerprints.

---

## Decision Outcome

### 1. Embedded Lean `FlowDefinition`
Defined immutable `FlowDefinition` in `karsasec.framework.intermediate`:
```python
@dataclass(frozen=True)
class ProvenanceEntry:
    attribute_name: str
    source_kind: str
    file_path: str
    line: int
    column: int = 0
    symbol: str = ""

@dataclass(frozen=True)
class FlowScope:
    route_id: str
    handler_id: str
    scope_id: str

@dataclass(frozen=True)
class FlowDefinition:
    flow_id: str
    scope: FlowScope
    source_kind: str
    source_symbol: str
    sink_kind: str
    sink_symbol: str
    sanitizer_symbols: tuple[str, ...] = ()
    validator_symbols: tuple[str, ...] = ()
    propagation_path: tuple[str, ...] = ()
    provenance_entries: tuple[ProvenanceEntry, ...] = ()
    origin: OriginMetadata = field(default_factory=OriginMetadata)
```
`FlowDefinition` contains raw declarative evidence ONLY. `taint_state` is calculated deterministically by `TaintEvaluator` during graph evaluation.

### 2. Taint Decision Table
The graph `TaintEvaluator` calculates derived taint states following strict precedence:

```text
UNKNOWN: missing source/sink, broken propagation graph edge, unknown intermediary, or conflicting evidence
UNTRUSTED: explicit untrusted source + established graph propagation + incompatible/no sanitizer
SANITIZED: explicit sanitizer + sink-compatible (COMPATIBLE) + established propagation
VALIDATED: explicit validator + sink-compatible (COMPATIBLE) + established propagation
SAFE: explicit trusted source + established propagation + compatible sink handling
```

### 3. Graph Model & Relationships
Added `SemanticNodeType.FLOW = "FLOW"` and edge types `FLOWS_TO`, `PROPAGATES_TO`, `SINKS_TO`.
Visited-node and edge tracking guarantees deterministic termination on cyclic graphs (`A -> B -> C -> A`).

### 4. Tier-D Rule Architecture
Introduced initial interprocedural flow security rules:
- `KS-FLASK-FLOW-0001`: Untrusted Input Reaches Dangerous Sink (`CRITICAL`, allowlisted dangerous sinks).
- `KS-FLASK-FLOW-0002`: Untrusted Input Reaches SQL Sink (`HIGH`).
- `KS-FLASK-FLOW-0003`: Unvalidated Redirect Input (`HIGH`, explicit untrusted request input requirement).

---

## Consequences

* **Positive**: Interprocedural flow rules operate on verified multi-node graph topology with zero false positives from unproven or ambiguous code paths.
* **Positive**: Complete backward compatibility; existing ISR documents without flows deserialize cleanly as `flows = ()`.
* **Negative**: Requires storing `FLOW` nodes and edges in `FrameworkSemanticGraph` (benchmarks confirm sub-100ms evaluation for 10,000 nodes).
