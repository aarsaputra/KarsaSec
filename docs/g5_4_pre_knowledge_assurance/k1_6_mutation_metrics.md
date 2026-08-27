# K1.6 Mutation Metrics Audit Report

## 1. Formal Taxonomy & Mutation Denominator Definition (`INV-K1.6-05`)
- **M1–M7**: Metamorphic Semantic Transformations
- **M8**: Adversarial Safe-Control Transformation (evaluated independently in safe-control FPR metrics)

The Mutation Kill-Rate is defined formally as:
$$\text{MutationKillRate} = \frac{\text{killed\_mutations}}{\text{eligible\_mutations}}$$
where eligible mutations include strictly valid Python AST cases, excluding syntax-invalid mutations.

## 2. Per-Class Mutation Kill-Rate Matrix (M1–M8)

| Mutation Category | Category Type | Total Generated | Eligible (Valid AST) | Killed | Missed | Kill Rate | Threshold | Verdict |
|:---|:---|---:|---:|---:|---:|---:|---:|:---:|
| M1 Identifier Renaming | Metamorphic | 11 | 11 | 11 | 0 | **100.0%** | $\ge 95\%$ | **PASS** |
| M2 Function Renaming | Metamorphic | 11 | 11 | 11 | 0 | **100.0%** | $\ge 95\%$ | **PASS** |
| M3 Assignment Aliasing | Metamorphic | 11 | 11 | 11 | 0 | **100.0%** | $\ge 90\%$ | **PASS** |
| M4 Equivalent Expression | Metamorphic | 11 | 11 | 11 | 0 | **100.0%** | $\ge 90\%$ | **PASS** |
| M5 Dead Code Insertion | Metamorphic | 11 | 11 | 11 | 0 | **100.0%** | $\ge 95\%$ | **PASS** |
| M6 Formatting Noise | Metamorphic | 11 | 11 | 11 | 0 | **100.0%** | $100\%$ | **PASS** |
| M7 Helper Wrapper | Metamorphic | 11 | 11 | 11 | 0 | **100.0%** | $\ge 90\%$ | **PASS** |
| M8 Safe-Control Trans | Safe-Control | 15 | 15 | 15 (safe) | 0 (FP) | **100.0%** | $100\%$ | **PASS** |

Verified via `tests/benchmark/test_k1_6_mutation_metrics.py`.
