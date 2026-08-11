# DVWA Benchmark Qualification Snapshots

This directory stores reproducible qualification result snapshots for the **DVWA (Damn Vulnerable Web Application)** benchmark.

---

## Snapshot Lifecycle

- **`latest.json`**: Updated when running `karsasec qualify --benchmark dvwa --save-snapshot`. Represents the output of the most recent qualification run.
- **`baseline.json`**: The immutable, human-verified qualification baseline. Must NEVER be automatically overwritten by standard scans or qualification CLI runs; updates to `baseline.json` require deliberate human action.

---

## Format Specification

Snapshots separate execution metadata from metric identity:

```json
{
  "benchmark": "dvwa",
  "version": "1.x",
  "karsasec_version": "0.1.0",
  "schema_version": "1.0",
  "cases": {
    "total": 32,
    "tp": 0,
    "fp": 0,
    "fn": 0,
    "tn": 0,
    "unknown": 0
  },
  "metrics": {
    "precision": 0.0,
    "recall": 0.0,
    "f1": 0.0
  },
  "finding_quality": {
    "raw_findings": 0,
    "final_findings": 0,
    "duplicate_findings": 0,
    "duplicate_rate": 0.0,
    "exact_duplicates": 0,
    "exact_duplicate_rate": 0.0,
    "cross_rule_overlaps": 0,
    "cross_rule_overlap_rate": 0.0,
    "unknown_rate": 0.0
  },
  "per_category": {},
  "per_rule": {}
}
```
