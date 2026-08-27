# Sprint E13 — Finding Correlation, Confidence Calibration & Vulnerability Evidence Graph Architecture

## 1. Executive Summary & Design Principles

Sprint E13 implements the **Evidence Correlation Layer** as an additive, deterministic security assessment layer built on top of the frozen E9-E12 foundations.

E13 transforms raw `SecurityFinding` objects into correlated `VulnerabilityCluster` representations, constructs an immutable `EvidenceGraph`, calibrates confidence based on evidence independence across 8 dimensions, and produces byte-for-byte reproducible `SecurityAssessment` reports.

### Key Architectural Commitments:
- **Zero Foundation Mutation**: E9 (CPG), E10 (SemanticFact), E11 (SemanticFlow), and E12 (SecurityFinding) remain strictly **FROZEN**.
- **$O(F+C)$ Target Complexity**: Finding correlation utilizes candidate indexes (`source_fact_id`, `sink_fact_id`, `flow_id`, `node_pair`) and deterministic Disjoint-Set / Union-Find (DSU) component merging.
- **Multi-Criteria Evidence Compatibility Guard**: Shared source alone reaching different sink vulnerability classes (e.g., HTTP param reaching SQL vs HTML render) will **NOT** merge into a single cluster (`INV-E13-CORR-26`).
- **Duplicate Evidence Isolation**: Duplicate findings from identical sources/sinks/flows do **NOT** inflate confidence (`INV-E13-CORR-07,27`).
- **Fail-Closed Security Posture**: Uses `ClusterStatus` (`CONFIRMED`, `CANDIDATE`, `BLOCKED`, `UNKNOWN`). **NEVER emits `SAFE`**.

---

## 2. Pipeline Architecture

```text
                  SecurityFindingStore (E12)
                             │
                             ▼
                    Build Candidate Index
       (source_fact, sink_fact, flow_id, node_pair, vuln_class)
                             │
                             ▼
                 Generate Candidate Pairs O(C)
                             │
                             ▼
               Evidence Compatibility Guard
                             │
                             ▼
                     Union-Find (DSU)
                             │
                             ▼
                  VulnerabilityCluster
                             │
                             ▼
                     EvidenceGraph
                             │
                             ▼
                 Confidence Calibration
                             │
                             ▼
                   SecurityAssessment
```

---

## 3. Data Models & Algorithms

### 3.1 `VulnerabilityCluster` (`karsasec/analysis/vulnerability_cluster.py`)
Immutable dataclass grouping correlated findings.
```python
@dataclass(frozen=True)
class VulnerabilityCluster:
    cluster_id: str  # SHA256("E13:" + canonical_json)
    vulnerability_class: str
    finding_ids: tuple[str, ...]
    source_fact_ids: tuple[str, ...]
    sink_fact_ids: tuple[str, ...]
    flow_ids: tuple[str, ...]
    source_nodes: tuple[str, ...]
    sink_nodes: tuple[str, ...]
    shared_contexts: tuple[tuple[str, ...], ...]
    confidence: float
    severity: str
    status: ClusterStatus  # CONFIRMED | CANDIDATE | BLOCKED | UNKNOWN
    evidence_count: int
```

### 3.2 Evidence Compatibility Guard (`karsasec/analysis/finding_correlator.py`)
```python
def evidence_compatible(a: SecurityFinding, b: SecurityFinding) -> bool:
    if a.vulnerability_class != b.vulnerability_class:
        return False
    if a.flow_id == b.flow_id and a.flow_id != "missing_flow":
        return True
    if a.source_fact_id == b.source_fact_id and a.sink_fact_id == b.sink_fact_id:
        return True
    if a.source_node_id == b.source_node_id and a.sink_node_id == b.sink_node_id:
        return True
    return False
```

### 3.3 Confidence Calibration Formula (`karsasec/analysis/confidence_calibrator.py`)
$$C_{\text{calibrated}} = \min\left(1.0, C_{\text{base}} + 0.10 \cdot S_{\text{indep}} + 0.10 \cdot K_{\text{indep}} + 0.05 \cdot Context_{\text{indep}} + 0.05 \cdot Corroboration\right)$$

Evidence diversity is measured across 8 unique dimensions:
- `SOURCE`, `SINK`, `FLOW`, `SSA`, `CALL_CONTEXT`, `SANITIZER`, `FRAMEWORK`, `RULE`.

---

## 4. Invariant Commitments (INV-E13-CORR-01..35)

- **INV-E13-CORR-01..03**: Deterministic SHA-256 IDs for cluster, node, and edge objects.
- **INV-E13-CORR-04,05,31**: Metamorphic input order and `PYTHONHASHSEED` independence.
- **INV-E13-CORR-07,27,32**: Duplicate findings do not inflate confidence.
- **INV-E13-CORR-18,19,34**: CPG graph topology remains 100% immutable.
- **INV-E13-CORR-26**: Shared source alone MUST NOT merge unrelated sink vulnerabilities.
- **INV-E13-CORR-35**: Assessment structured explanations are 100% reproducible byte-for-byte.
