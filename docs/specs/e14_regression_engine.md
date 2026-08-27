# Sprint E14 — Security Regression Engine Architecture

## Overview
The **Security Regression Engine** tracks vulnerability transitions between baseline and current analysis runs using line-number-independent semantic fingerprints (`RegressionFingerprint`) and thread-safe persistence (`SecurityRegressionStore`).

## Line-Independent Semantic Fingerprinting

`RegressionFingerprint` uniquely identifies findings regardless of code refactoring, line number movements, or file re-indentations:

$$
\text{FingerprintID} = \text{SHA256}\left(\text{"E14-FINGERPRINT:"} + \text{CanonicalJSON}(V_C, \text{SourceKind}, \text{SinkCategory}, \text{NormalizedPath}, \text{RuleKey}, \text{CallContext})\right)
$$

### Canonical Path Normalization
File paths undergo standard normalization before fingerprinting:
1. Stripping trailing line/col numbers (`:42`, `:1000`, `:10:5`).
2. Unifying path separators (`\` $\rightarrow$ `/`).
3. Resolving relative parent dot components (`foo/../foo/app.py` $\rightarrow$ `foo/app.py`).
4. Stripping leading `./`.

## Regression State Machine

Transitions between baseline fingerprints $B$ and current fingerprints $C$ are classified into 5 discrete states:

```
                 ┌───────────┐
                 │    NEW    │  (C present, B absent)
                 └─────┬─────┘
                       │
                       ▼
                ┌──────────────┐
                │  PERSISTENT  │  (C present, B present)
                └──────┬───────┘
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       CHANGED      RESOLVED     UNKNOWN
```

### Strict RESOLVED Semantics Guard
- `RESOLVED` requires: Baseline fingerprint present AND current analysis completed successfully (`current_analysis_valid == True`) AND baseline fingerprint explicitly absent in current findings.
- **Fail-Closed Guard**: If current analysis failed, crashed, or missing evidence (`current_analysis_valid == False`), missing baseline fingerprints are classified as `UNKNOWN`, **NEVER `RESOLVED`**.

## Thread-Safe Store Synchronization

`SecurityRegressionStore` provides thread-safe access with lock-protected `insert-if-absent` synchronization (`add`), ensuring that concurrent insertions of identical fingerprints produce exactly one logical record.
