# K1.5 Positive Adversarial Corpus Report

## 1. Corpus Overview
A separate 20-case positive adversarial corpus (`benchmarks/k1/adversarial_positive/`) was created to test detection recall under heavy syntax, identifier, and structural variations.

- **JWT (7 cases)**: `adv-pos-jwt-001.py` through `007.py`
- **OAuth (6 cases)**: `adv-pos-oauth-001.py` through `006.py`
- **Business Logic (7 cases)**: `adv-pos-biz-001.py` through `007.py`

## 2. Evaluation Results
- **Detected True Positives**: 20 / 20 cases
- **Adversarial Recall**: **1.0000** (Threshold: >= 0.95)
- **False Negatives**: **0**

Verified via `tests/benchmark/test_k1_5_adversarial_positive.py`.
