# KarsaSec Architecture Baseline — Frozen 2026-08-23

> This document records the immutable reference point for the Chief Architect's
> Phase 0–4 validation program. No structural changes to D1–D6 engines are
> permitted during the validation window except those explicitly mandated by
> Phase 2 (D4 causality hardening) and Phase 4 (D6 risk model separation).

## Frozen Baseline

| Metric | Value |
|:---|:---|
| **Commit SHA** | `cbbb7fe4d088cd55212e97fe7928847103892d97` |
| **Date** | 2026-08-23 |
| **Total Tests** | 11,002 |
| **Test Runtime** | 133.90s |
| **Ruff** | Clean (0 errors) |
| **F9 Zero-Diff** | Verified (0 files changed) |

## Branch Coverage Baseline (Measured via `coverage run --branch`)

| Engine | File | Stmts | Miss | Branch | BrPart | Cover |
|:---|:---|:---:|:---:|:---:|:---:|:---:|
| D1 | `invariants/engine.py` | 79 | 26 | 72 | 14 | **60%** |
| D2 | `temporal/engine.py` | 75 | 13 | 72 | 5 | **81%** |
| D3 | `distributed/engine.py` | 113 | 29 | 102 | 16 | **71%** |
| D4 | `correlation/engine.py` | 157 | 14 | 78 | 14 | **86%** |
| D5 | `proof/engine.py` | 111 | 2 | 50 | 4 | **96%** |
| D6 | `decision/engine.py` | 106 | 0 | 46 | 0 | **100%** |

## Complexity Assessment

| Engine | Worst-Case Time | Worst-Case Space |
|:---|:---|:---|
| D4 | O(V log V + E log E) | O(V + E) |
| D5 | O(V + E) | O(1) |
| D6 | O(N log N) | O(N) |

## Architectural Principles (Frozen)

1. `correlation ≠ causation` — D4 produces CORRELATED, not CAUSED
2. `UNKNOWN ≠ SAFE` and `UNKNOWN ≠ VULNERABLE` — epistemic states are never inflated
3. `CONFLICT ≠ SAFE` and `CONFLICT ≠ VULNERABLE` — contradictions are preserved
4. All engines are read-only, deterministic, static, side-effect-free
5. No network, subprocess, shell, SQL, eval, exec calls permitted in `karsasec/analysis/`
6. `UNKNOWN` business risk must NOT collapse to LOW risk
