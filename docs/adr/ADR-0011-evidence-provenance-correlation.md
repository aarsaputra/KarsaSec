# ADR-0011: Evidence Quality, Provenance, and Finding Correlation Hardening

## Status
Accepted

## Date
2026-08-11

## Context
In Sprint E12-3, KarsaSec established the `SemanticFindingQualifier` pipeline, deterministic FP taxonomy (`FPTaxonomyReason`), and baseline metrics qualification. However, security finding correlation and evidence completeness faced several operational challenges:

1. **Evidence Provenance & Completeness**: Candidate findings transformed into qualified findings sometimes lost context regarding untrusted sources, taint paths, or sanitizer capabilities.
2. **Finding Identity & Deduplication**: Using only `(file, line, rule_id)` for deduplication caused duplicate reports when multiple distinct rules detected the same underlying semantic vulnerability at the same sink location, while merging different vulnerability categories at the same file/line could erroneously suppress valid findings.
3. **Evidence Conflicts**: When rule matches or taint analyzers produced contradictory interpretations (e.g. `TAINTED` vs `SANITIZED` or `COMMAND_EXECUTION` vs `SQL_EXECUTION`), system behavior needed to remain safe without making arbitrary assumptions or suppressing candidates silently.

## Decision

We establish the following architectural standards for evidence quality, provenance, and finding correlation:

### 1. Evidence Provenance Model & Explicit Semantics
Every `QualifiedFinding` carries enriched `FindingEvidence` recording:
- `rule_id`, `node_type`, `matched_text`
- `sink_symbol`, `sink_category`
- `source_symbol`, `source_category`
- `taint_state`, `taint_path` (tuple of hops)
- `sanitizer_symbol`, `sanitizer_capability`
- `constant_resolution`
- `qualification_state`, `rejection_reason`

Where information is unavailable or not relevant, explicit field states are assigned (`KNOWN`, `UNKNOWN`, `NOT_APPLICABLE`) rather than converting missing data into false certainty.

### 2. Evidence Completeness Validation (`EvidenceCompleteness`)
A deterministic validator verifies whether a finding carries sufficient evidence for its assigned state:
- `CONFIRMED`: Must possess valid sink location and either detected untrusted source or justified security constraint.
- `REJECTED`: Must record an explicit `FPTaxonomyReason`.
- `UNRESOLVED`: Must possess explicit explanation/conflict evidence. Missing evidence never defaults to "safe".

### 3. Canonical Finding Identity
We define two distinct identity models:
- **Exact Identity**: `(normalized_file, line, rule_id)`. Used for exact candidate match deduplication.
- **Semantic Identity**: `(normalized_file, sink_line, sink_category, canonical_sink, canonical_taint_path)`. Used for cross-rule semantic deduplication.

Path normalization replaces `\` with `/`, strips redundant `./` segments, and normalizes repository paths.

### 4. Correlation Policy & 4-Case Handling (`FindingCorrelator`)
- **Case A — Exact Duplicate**: Identical `(file, line, rule_id)` → collapse into single finding.
- **Case B — Semantic Duplicate**: Same `file`, `sink_line`, `sink_category`, and equivalent canonical taint path across different rules → correlate into one primary `CanonicalFinding` while preserving all `contributing_rule_ids` and evidence.
- **Case C — Independent Vulnerabilities**: Different `sink_category` or materially distinct taint paths → maintain as separate findings even at the same line.
- **Case D — Evidence Conflict**: Contradictory evidence (e.g., `TAINTED` vs `SANITIZED`) → enforce `CONFLICT → UNKNOWN → UNRESOLVED` transition with an explicit `EvidenceConflict` attached.

### 5. Invariants & Recall Protection Gates
- **Ground Truth Immutability**: `benchmarks/dvwa/manifest.yaml` and `baseline.json` are immutable references.
- **Zero DVWA-Specific Hardcoding**: All path normalization and correlation logic must remain generic.
- **Recall Protection Gates**:
  - Command Injection Recall ≥ 100%
  - Path Traversal Recall = 100%
  - SQL Injection Recall ≥ 85%
  - Overall Recall ≥ 70%

## Consequences

### Positive
- 100% auditable evidence trail for every reported vulnerability.
- Eliminates duplicate findings across overlapping OWASP and language-specific rules without losing contributing rule metadata.
- Prevents false certainty when evidence is contradictory.
- Maintains strict backward compatibility and deterministic output across multiple scan runs.

### Negative
- Slightly higher memory footprint due to detailed evidence hop tracking and conflict preservation (mitigated by frozen dataclasses and tuple structures).
