# K1.6 Dominating Safe-Control Semantic Negative Audit Report

## 1. Overview (`INV-K1.6-06`)
15 complex negative adversarial fixtures in `benchmarks/k1/adversarial_semantic_negative/` were evaluated. Every fixture contains vulnerability-looking syntax, realistic dangerous sinks, and explicit security controls dominating the sink (authorization checks, role checks, allowlists, state validation, transaction locks, public key verification).

## 2. Evaluation Results

| Domain | Cases Evaluated | Dominating Security Controls | False Positives | FPR | Verdict |
|:---|---:|:---|---:|---:|:---:|
| Business Logic | 8 | DB price lookup, super admin role, owner validation, pessimistic transaction lock, state guard, range guard, single-use coupon, decorator authz | 0 | **0.0%** | **PASS** |
| OAuth Protocol | 4 | URL allowlist, CSRF state check, single-use code, scope allowlist | 0 | **0.0%** | **PASS** |
| JWT Token Parsing | 3 | RS256 public key verification, exp/iss claim verification, Bearer RS256 signature | 0 | **0.0%** | **PASS** |
| **Total** | **15** | | **0** | **0.0%** | **PASS** |

Verified via `tests/benchmark/test_k1_6_semantic_negative.py`.
