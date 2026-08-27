# Sprint E15 — Security Decision Orchestration Architecture & Fail-Closed Gate Specification

## Executive Overview
Sprint E15 establishes an automated, fail-closed **Security Decision Gate** and **Orchestration Layer** operating additively on top of the certified KarsaSec analysis foundation (E9–E14). 

The primary objective of E15 is to convert raw vulnerability evidence, prioritization scores, remediation plans, and regression reports into deterministic, auditable security release decisions:
- `ALLOW`: Code meets all security standards; release approved.
- `BLOCK`: High-risk or regressed security findings must block deployment.
- `REVIEW`: Manual security review is required due to boundary conditions or missing context.
- `UNKNOWN`: Default fail-closed state when input data is incomplete, corrupted, or out-of-bounds.

## Architectural Invariants
1. **0% Baseline Mutation**: E15 consumes E9–E14 objects as read-only inputs. No E9–E14 classes or functions are modified or mutated.
2. **Fail-Closed Semantics**: Any missing, invalid, or corrupted evidence automatically yields an `UNKNOWN` or `BLOCK` decision. Never defaults to `ALLOW`.
3. **Pure Logic & Zero Dynamic Execution**: No `eval()`, `exec()`, network access, shell commands, or LLM-driven non-deterministic decisions.
4. **Deterministic Identity**: Every `SecurityDecision` and `SecurityGateResult` receives a deterministic SHA-256 hash computed over its canonical parameters.

## Core Modules & Design
- `e15_models.py`: Immutable dataclasses (`SecurityDecision`, `SecurityGateResult`, `DecisionStatus`).
- `e15_evidence_validator.py`: Enforces data completeness and guards against `NaN`/`Inf`/negative/out-of-bounds scores.
- `e15_exploitability.py`: Deterministic exploitability assessment engine.
- `e15_security_policy.py`: Security policy rules and threshold engine.
- `e15_security_gate.py`: 10-step decision hierarchy orchestrator.
- `e15_decision_audit.py`: Thread-safe, append-only decision ledger.

## 10-Step Fail-Closed Decision Hierarchy
1. **Rule 01 — Structural Integrity**: Inputs must be non-None and non-empty.
2. **Rule 02 — Evidence & Score Bounds**: Reject NaN, Inf, and out-of-bounds scores (`[0.0, 1.0]`).
3. **Rule 03 — Exploitability Validity**: Validate reachability and exploitability inputs.
4. **Rule 04 — Upstream State Known**: Ensure priority, remediation, and regression statuses are known.
5. **Rule 05 — Strict Regression Barrier**: If regression status is `FAIL`, force `BLOCK`.
6. **Rule 06 — Critical Severity Gate**: `CRITICAL` confirmed vulnerabilities with valid exploitability force `BLOCK` or `REVIEW` based on policy.
7. **Rule 07 — Blocked Remediation Gate**: If remediation plan status is `BLOCKED`, force `BLOCK`.
8. **Rule 08 — High Risk Review Gate**: `HIGH` priority findings with elevated exploitability force `REVIEW` or `BLOCK`.
9. **Rule 09 — Required Remediation Gate**: `CONFIRMED` vulnerabilities requiring remediation force `REVIEW` or `BLOCK`.
10. **Rule 10 — Fallthrough Default**: Safe low-risk confirmed states default to policy evaluation (`ALLOW` or `REVIEW`).
