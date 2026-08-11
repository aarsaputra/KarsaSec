# Sprint E12-4 — Evidence Provenance Architecture & Specification

## 1. Overview

Sprint E12-4 hardens KarsaSec's security finding pipeline so that every finding is evidence-backed, traceable, deterministic, semantically deduplicated, conflict-aware, and auditable.

---

## 2. Evidence Provenance Model

Every `QualifiedFinding` encapsulates an immutable `FindingEvidence` object containing:

* **Location Metadata**: `snippet`, `line`, `column`, `rule_id`, `node_type`, `matched_text`
* **Sink Provenance**: `sink_symbol`, `sink_category`
* **Source Provenance**: `source_symbol`, `source_category`
* **Taint Flow Provenance**: `taint_state` (`TAINTED` | `UNTAINTED` | `SANITIZED` | `UNKNOWN`), `constant_resolution` (`TAINTED` | `STATIC` | `DYNAMIC`)
* **Sanitizer Provenance**: `sanitizer_symbol`, `sanitizer_capability`
* **Qualification Trail**: `ast_match`, `semantic_match`, `qualification_state`, `rejection_reason`

### Explicit Provenance Status

Missing data is never misinterpreted as safe. `EvidenceCompleteness` validates provenance completeness using `ProvenanceStatus`:
* `KNOWN`: Full provenance verified.
* `UNKNOWN`: Incomplete provenance (e.g. unknown data flow).
* `NOT_APPLICABLE`: Non-taint vulnerability rules.

If evidence completeness evaluation fails for `CONFIRMED` findings, the finding transitions to `UNRESOLVED` state.

---

## 3. Dual Identity & Path Normalization

KarsaSec maintains two complementary identities per finding via `CanonicalFindingIdentity`:

1. **Exact Identity**:
   `hash(normalized_file | line | rule_id)`
   Used for raw deduplication across identical execution rules.

2. **Semantic Identity**:
   `hash(normalized_file | line | cwe_id | sink_category | sink_symbol | canonical_taint_path)`
   Used for cross-rule deduplication and semantic correlation.

### Path Normalization

`normalize_finding_path(path)` standardizes all paths across Windows and Linux:
* Windows backslashes (`\`) are converted to forward slashes (`/`).
* Redundant relative segments (`.`, `..`) are collapsed deterministically.
* Lowercased on Windows for case-insensitive filesystem equivalence.

---

## 4. Four-Case Finding Correlation

`FindingCorrelator` groups findings into exact and semantic equivalence classes:

* **Case A — Exact Duplicate**: Same `file`, `line`, `rule_id` → Collapsed.
* **Case B — Semantic Duplicate**: Same `file`, `line`, `sink_category`, equivalent taint path → Merged into primary finding while preserving all `correlated_rules`.
* **Case C — Different Vulnerabilities**: Different `sink_category` or materially different taint path → Retained as separate findings.
* **Case D — Conflicting Evidence**: Contradictory evidence across rules (e.g. `TAINTED` vs `SANITIZED` or `CONFIRMED` vs `REJECTED`) → Transitions finding to `UNRESOLVED` state with an attached `EvidenceConflict` object.

---

## 5. Conflict Resolution Safety Invariant

**Invariant**: `CONFLICT → UNKNOWN → UNRESOLVED`.

Rule disagreements are never resolved by silent suppression or arbitrary voting. Contradictory evidence creates an explicit `EvidenceConflict` object recorded in the finding's audit metadata and sets the finding state to `QualificationState.UNRESOLVED`.
