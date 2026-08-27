# Sprint E10: Additive Framework Semantic Extractors — Architecture Specification

## Executive Summary
Sprint E10 establishes an additive, deterministic, framework-aware semantic extraction layer on top of the certified and frozen **Sprint E9 / E9.5** infrastructure (`CPGIndex`, `QueryOptimizer`, `MultiHopTraversalEngine`).

$$\text{Source Code} \xrightarrow{\text{FrameworkDetector}} \text{KNOWN/UNKNOWN} \xrightarrow{\text{Extractors}} \text{SemanticFactStore} \xrightarrow{\text{CPG Attachment}} \text{CPGIndex Pushdown} \xrightarrow{\text{QueryOptimizer}}$$

---

## Architectural Principles & Mandatory Guards

1. **Additive Layer**: E10 builds upward from E9. E9 infrastructure (`CPGIndex`, `QueryOptimizer`, `MultiHopTraversalEngine`, index pushdown, SSA isolation, call-context state isolation) is **certified and frozen**.
2. **Authoritative `SemanticFactStore`**: `SemanticFact` objects maintain independent identity via SHA-256 digests (`SHA256(schema:framework:kind:file:line:symbol:canonical_metadata)`), decoupled from mutable `CPGNode.attributes`.
3. **Strict Boundary for `UNKNOWN`**: Ambiguous evidence produces `DetectionResult = UNKNOWN`, leading extractors to emit NO fabricated facts. Extractors extract facts; security findings are emitted exclusively by downstream Query/Rule execution (`INV-E10-SEM-07`).
4. **100% Deterministic Evidence Scoring**: Confidence is computed via explicit evidence scoring (`sum(evidence_scores)` rounded to 4 decimals) or canonical enum levels (`HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`). Fact ID calculation uses SHA-256 over canonical JSON serialization.
5. **E9 Non-Regression Contract**: Modifications to `index.py` for semantic attribute indexing (`by_semantic_role`) strictly preserve E9 query optimizer contracts, verified by running `pytest tests/unit/query/ -v` after every step.

---

## Core Components

### 1. Canonical Data Model (`SemanticFact` & `SemanticFactStore`)
- `karsasec/framework/semantic_fact.py`
- Holds normalized fields: `fact_id`, `kind`, `framework`, `semantic_role`, `symbol`, `file`, `line`, `node_id`, `metadata`, `source_kind`, `sink_category`, `confidence`, `confidence_level`.
- `SemanticFactStore`: Manages facts deterministically, handles deduplication, and attachment to `CPGGraph`.

### 2. Framework Detector (`FrameworkDetector`)
- `karsasec/framework/detector.py`
- Evidence-based detection using deterministic evidence weights (`import: 0.30`, `decorator: 0.30`, `api: 0.25`, `dependency: 0.15`).

### 3. Specialized Extractors
- `HTTPEndpointExtractor` (`karsasec/framework/extractors/endpoint_extractor.py`)
- `HTTPInputSourceExtractor` (`karsasec/framework/extractors/input_extractor.py`)
- `SecuritySinkExtractor` (`karsasec/framework/extractors/sink_extractor.py`)
- `AuthSemanticExtractor` (`karsasec/framework/extractors/auth_extractor.py`)
- `MiddlewareSemanticExtractor` (`karsasec/framework/extractors/middleware_extractor.py`)
- `ConfigurationSemanticExtractor` (`karsasec/framework/extractors/config_extractor.py`)

---

## Invariants Checklist (`INV-E10-SEM-01..17`)

- **INV-E10-SEM-01**: Deterministic Fact IDs across runs.
- **INV-E10-SEM-02**: Fact ID stability across multiple `PYTHONHASHSEED` values.
- **INV-E10-SEM-03**: `Extract(G) == Extract(G)` idempotency (`INV-E10-SEM-15`).
- **INV-E10-SEM-04**: `UNKNOWN` framework yields zero fabricated facts (Guard 2 & `INV-E10-SEM-07`).
- **INV-E10-SEM-08**: Error isolation — an exception in one extractor leaves others unharmed.
- **INV-E10-SEM-13**: `SemanticFact.node_id ∈ CPGGraph.nodes`.
- **INV-E10-SEM-14**: Semantic extraction MUST NOT mutate CPG topology (node/edge count).
- **INV-E10-SEM-15**: Repeated extraction MUST NOT duplicate facts in `SemanticFactStore`.
- **INV-E10-SEM-16**: Unrelated source code addition does not alter existing fact IDs.
- **INV-E10-SEM-17**: `CPGIndex` lookup after semantic attachment remains equivalent to authoritative CPG graph search.
