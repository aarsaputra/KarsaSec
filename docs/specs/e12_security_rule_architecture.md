# Sprint E12 — Semantic Rule Evaluation & Security Finding Engine Architecture

## 1. Executive Summary & Design Principles

Sprint E12 introduces the **Semantic Rule Evaluation & Security Finding Engine** as an additive, deterministic security decision layer built directly on top of the frozen E9-E11 foundation (CPGGraph, SemanticFactStore, and SemanticFlowStore).

E12 operates as a fail-closed state machine transforming correlated semantic evidence into immutable, forensic `SecurityFinding` objects. It guarantees:
- **100% Deterministic Rule and Finding IDs**: Identity is derived via canonical SHA-256 serialization.
- **Fail-Closed Security Posture**: `UNKNOWN` findings are emitted whenever node, fact, or flow integrity is compromised (`UNKNOWN != SAFE`).
- **Sink-Category-Specific Barrier Matrix**: Sanitizers are validated strictly against target sink categories (e.g. `int()` for `sql`, `shlex.quote()` for `command_execution`, `escape_html()` for `html_render`). Fake sanitizers (`str()`, `trim()`) and cross-category sanitizers are explicitly rejected as barriers.
- **$O(F + C)$ Matching Complexity**: `SecurityRuleRegistry` maintains indexed candidate lookup by `(source_kind, sink_category)`.
- **Zero CPG Graph Mutation**: Graph node and edge counts are verified to remain immutable during rule evaluation.

---

## 2. Pipeline Architecture

```text
               Source Code
                    │
                    ▼
          E10 SemanticFactStore
                    │
          E11 SemanticFlowStore
                    │
                    ▼
          SecurityRuleRegistry
            (Indexed O(1) Lookup)
                    │
                    ▼
        SemanticRuleEngine Evaluation
         ├── RuleCondition Checking
         ├── Sanitizer Barrier Matrix
         └── Deterministic Confidence
                    │
                    ▼
           SecurityFindingStore
       (Deduplicated & Forensic Audit)
```

---

## 3. Core Data Models

### 3.1 `SecurityRule` (`karsasec/analysis/security_rule.py`)
Immutable dataclass representing declarative rule criteria:
```python
@dataclass(frozen=True)
class SecurityRule:
    rule_id: str  # SHA256("E12:" + rule_key + ":" + version)
    rule_key: str  # e.g., "E12-SQL-001"
    name: str
    version: str
    vulnerability_class: str
    source_kinds: tuple[str, ...]
    sink_categories: tuple[str, ...]
    required_roles: tuple[str, ...]
    blocked_by_sanitizers: tuple[str, ...]
    minimum_confidence: float
    severity: str
    conditions: tuple[RuleCondition, ...]
```

### 3.2 `SecurityFinding` (`karsasec/analysis/security_finding.py`)
Immutable dataclass capturing forensic evidence and decision traces:
```python
@dataclass(frozen=True)
class SecurityFinding:
    finding_id: str  # SHA256(canonical_payload)
    rule_id: str
    rule_key: str
    rule_version: str
    vulnerability_class: str
    source_fact_id: str
    sink_fact_id: str
    flow_id: str
    source_node_id: str
    sink_node_id: str
    severity: str
    status: FindingStatus  # CONFIRMED | CANDIDATE | BLOCKED | UNKNOWN
    confidence: float
    source_evidence: tuple[tuple[str, str], ...]
    sink_evidence: tuple[tuple[str, str], ...]
    flow_evidence: tuple[tuple[str, str], ...]
    sanitizer_evidence: tuple[tuple[str, str], ...]
    condition_evidence: tuple[tuple[str, str], ...]
```

---

## 4. Sink-Category-Specific Barrier Matrix

| Sink Category | Valid Sanitizer / Barrier | Result |
| :--- | :--- | :--- |
| `sql` | `int()`, `sanitize_sql()`, `parameterized_query`, `prepared_statement` | `BLOCKED` |
| `command_execution` | `shlex.quote()`, `command_allowlist`, `safe_exec` | `BLOCKED` |
| `html_render` | `escape_html()`, `html_escape()`, `framework_auto_escape` | `BLOCKED` |
| `file_path` | `path_allowlist()`, `realpath_boundary_check()`, `safe_join()`, `basename()` | `BLOCKED` |
| `code_execution` | `strict_allowlist()`, `static_dispatch()`, `ast.literal_eval()` | `BLOCKED` |
| **Fake / Any** | `str()`, `trim()`, `lower()`, `upper()` | **NOT BLOCKED** |
| **Cross-Category** | `escape_html()` on `sql` or `sanitize_sql()` on `command_execution` | **NOT BLOCKED** |

---

## 5. Decision & Confidence Algorithms

### Confidence Calculation Formula:
$$\text{Confidence} = \text{round}(0.25 \cdot S_{\text{src}} + 0.25 \cdot S_{\text{snk}} + 0.20 \cdot R + 0.10 \cdot SSA + 0.10 \cdot Context + 0.05 \cdot FW + 0.05 \cdot San, 4)$$

### Finding Status Decision Tree:
```text
IF integrity invalid OR source/sink fact missing OR flow.status == UNKNOWN:
    emit FindingStatus.UNKNOWN
ELIF valid_sink_specific_sanitizer_exists:
    emit FindingStatus.BLOCKED
ELIF confidence >= 0.85:
    emit FindingStatus.CONFIRMED
ELIF confidence >= 0.60:
    emit FindingStatus.CANDIDATE
ELSE:
    emit FindingStatus.UNKNOWN
```
