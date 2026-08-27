# K1.5 Negative Adversarial Corpus Report

## 1. Corpus Overview
A separate 20-case negative adversarial corpus (`benchmarks/k1/adversarial/`) was created to test false-positive resistance against indirect safe controls, helper functions, and complex safe abstractions.

- **JWT (7 cases)**: `adv-neg-jwt-001.py` through `007.py`
- **OAuth (6 cases)**: `adv-neg-oauth-001.py` through `006.py`
- **Business Logic (7 cases)**: `adv-neg-biz-001.py` through `007.py`

## 2. Evaluation Results
- **Protected True Negatives**: 20 / 20 cases
- **Adversarial Precision**: **1.0000** (Threshold: >= 0.95)
- **Adversarial FPR**: **0.0000** (Threshold: <= 0.05)
- **False Positives**: **0**

Verified via `tests/benchmark/test_k1_5_adversarial_negative.py`.
