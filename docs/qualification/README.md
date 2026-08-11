# KarsaSec Security Qualification System

The **Qualification System** (`karsasec.qualification`) provides deterministic, machine-readable measurement of KarsaSec detection quality across standardized vulnerability benchmarks.

---

## Purpose

1. **Deterministic Quality Measurement**: Evaluate scanner output against manually verified ground-truth cases.
2. **Standardized Metrics**: Compute Precision, Recall, F1 score, and Duplicate Finding Rate globally and per rule.
3. **Anti-Circularity**: Ground truth is established independently via manual review and is never auto-generated from KarsaSec scan output.
4. **CI/CD Quality Gate**: Serve as an objective quality gate before multi-framework expansion (E10-4) and incremental analysis (E11).

---

## Quick Start

```bash
# Run DVWA benchmark qualification
karsasec qualify --benchmark dvwa --target /path/to/dvwa/vulnerabilities

# Output machine-readable JSON for CI integration
karsasec qualify --benchmark dvwa --target /path/to/dvwa/vulnerabilities --format json
```

---

## Architecture Overview

```text
                  Ground Truth Manifest (YAML)
                             │
                             ▼
  KarsaSec Scan ──► FindingCorrelator ──► QualificationEngine
                                                 │
                                                 ├── ClassificationReport (TP / FP / FN / TN)
                                                 └── QualificationResult (P / R / F1 / Dup Rate)
```

---

## Core Principles

- **No Anti-Circularity Violation**: Manifests are authored by humans based on source code analysis.
- **Exact Line Identity**: Finding identities match `(normalized_file, line, rule_id)`. Unstable fields (messages, timestamps, generated UUIDs) are ignored.
- **Separate UNKNOWN Tracking**: Findings with `UNKNOWN` confidence are tracked in a dedicated bucket and never forced into TP or FP.
- **Zero-Division Safety**: All metric formulas handle zero-denominator cases safely without raising division errors.
