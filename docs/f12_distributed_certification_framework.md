# Sprint F12 — Distributed Certification Framework

## Executive Summary
Sprint **F12** implemented the **Distributed Certification Framework** for the KarsaSec platform.

This framework enforces fail-closed, monotonic release boundary and integrity verification across distributed authority nodes, PostgreSQL transactional persistence engines, fencing tokens, and cluster state transitions.

---

## 1. Governance & Architecture Alignment
- **Master PRD Compliance**: Aligns with **MASTER_PRD.md** (Track C: Distributed Systems Assurance).
- **Core Engine Module**: [`karsasec/analysis/distributed/certification.py`](karsasec/analysis/distributed/certification.py)
- **Primary Guard Class**: `DistributedCertificationReleaseGuard`
- **Convenience Verifier**: `verify_distributed_certification_integrity()`

---

## 2. Invariants Enforced (`INV-F12-01` to `INV-F12-08`)

1. **`INV-F12-01` (Distributed Precondition Check)**: All cluster node state transitions must pass certification integrity checks before processing transactions.
2. **`INV-F12-02` (Fail-Closed Cluster Authority)**: Any integrity failure, missing manifest, or tampering evaluates to `DistributedGateState.BLOCKED`.
3. **`INV-F12-03` (Fencing Token Monotonicity)**: Stale or decremented fencing tokens (`fencing_token < expected`) evaluate to `BLOCKED / STALE_TOKEN`.
4. **`INV-F12-04` (Cluster Evidence Immutability)**: Read-only byte hashing of manifest digests ($\Delta \text{bytes} = 0$).
5. **`INV-F12-05` (Deterministic Decision)**: Identical cluster state yields 100% deterministic certification results.
6. **`INV-F12-06` (Explicit Failure Reason)**: Failure reason explicitly categorizes error (`DRIFTED`, `MISSING`, `INVALID`, `STALE_TOKEN`, `SPLIT_BRAIN_RISK`).
7. **`INV-F12-07` (Monotonic State Machine)**: Once a `DistributedCertificationReleaseGuard` instance transitions to `BLOCKED`, it remains `BLOCKED` for that node's execution context.
8. **`INV-F12-08` (Split-Brain Protection)**: Detected split-brain conditions evaluate to `BLOCKED / SPLIT_BRAIN_RISK`.

---

## 3. Verification & Test Matrix

Implemented in [`tests/distributed/test_f12_distributed_certification.py`](tests/distributed/test_f12_distributed_certification.py):

| Test ID | Description | Expected Outcome | Actual Outcome | Status |
|:---|:---|:---:|:---:|:---:|
| **F12-01** | Valid Cluster Integrity | `READY / VALID` | `READY / VALID` | **PASS** |
| **F12-02** | Split-Brain Protection | `BLOCKED / SPLIT_BRAIN_RISK` | `BLOCKED / SPLIT_BRAIN_RISK` | **PASS** |
| **F12-03** | Stale Fencing Token | `BLOCKED / STALE_TOKEN` | `BLOCKED / STALE_TOKEN` | **PASS** |
| **F12-04** | Missing Manifest Path | `BLOCKED / MISSING` | `BLOCKED / MISSING` | **PASS** |
| **F12-05** | Trust Anchor Mismatch | `BLOCKED / INVALID` | `BLOCKED / INVALID` | **PASS** |
| **F12-06** | Tampered Manifest SHA256 | `BLOCKED / INVALID` | `BLOCKED / INVALID` | **PASS** |
| **F12-07** | Monotonic Guard State | `BLOCKED` (Remains `BLOCKED`) | `BLOCKED` (Remains `BLOCKED`) | **PASS** |
| **F12-08** | Exception Handling Safety | `BLOCKED / INVALID` | `BLOCKED / INVALID` | **PASS** |

---

## 4. Status

$$\mathbf{F12\_DISTRIBUTED\_CERTIFICATION\_CERTIFIED}$$
