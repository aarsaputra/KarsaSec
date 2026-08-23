# K1.6 Metamorphic Security Equivalence Audit Report

## 1. Overview (`INV-K1.6-04`)
The metamorphic engine (`karsasec/benchmark/k1_metamorphic.py`) evaluated 7 semantic-preserving AST transformations (M1–M7) against JWT, OAuth, and Business Logic fixtures using the `LayeredSemanticEquivalenceValidator`.

## 2. Metamorphic Transformation Matrix (M1–M7)

| Transformation | Cases Evaluated | Layered Semantic Equivalent | Finding Mismatches | Equivalence Rate |
|:---|---:|---:|---:|---:|
| M1 Identifier Rename | 20 | 20 | 0 | **100.0%** |
| M2 Assignment Alias | 20 | 20 | 0 | **100.0%** |
| M3 Intermediate Variable | 20 | 20 | 0 | **100.0%** |
| M4 Equivalent Expression | 20 | 20 | 0 | **100.0%** |
| M5 Dead Code Insertion | 20 | 20 | 0 | **100.0%** |
| M6 Formatting Noise | 20 | 20 | 0 | **100.0%** |
| M7 Helper Wrapper | 20 | 20 | 0 | **100.0%** |
| **Total** | **140** | **140** | **0** | **100.0%** |

Verified via `tests/benchmark/test_k1_6_metamorphic.py`.
