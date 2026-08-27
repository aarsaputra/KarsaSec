# KarsaSec D1–D6 Contract & Invariant Inventory

> Architectural contract for the reasoning pipeline.
> Each layer's input/output/invariant/epistemic/mutation contracts are defined here.
> This document governs what agent coding may and may not change.

## D1 — Security Invariant Engine

| Property | Specification |
|:---|:---|
| **Input** | C13 attack graph, C14 privilege graph, C15 breach scenario, raw findings |
| **Output** | `list[InvariantViolation]` — frozen immutable violation objects |
| **Invariants** | INV-D1-01 through INV-D1-18 (privilege boundary, authorization, authentication, input validation, session, crypto, access control) |
| **Epistemic States** | VIOLATED / NOT_VIOLATED / UNKNOWN |
| **Mutation Policy** | NONE — read-only, deep-copy immutability verification |
| **Complexity** | O(N × I) where N = findings, I = invariants evaluated |
| **Security Assumption** | Invariant definitions are correct and complete for the target vulnerability class |
| **Known Limitation** | Invariant set is static; no learning or adaptive invariant discovery |

---

## D2 — Temporal & State Consistency Engine

| Property | Specification |
|:---|:---|
| **Input** | D1 violations, raw findings with temporal metadata |
| **Output** | `list[TemporalViolation]` — frozen immutable temporal inconsistency objects |
| **Invariants** | Temporal ordering, state transition validity, race condition detection |
| **Epistemic States** | TEMPORAL_VIOLATION / CONSISTENT / UNKNOWN |
| **Mutation Policy** | NONE — read-only, deep-copy immutability verification |
| **Complexity** | O(N log N) dominated by temporal sorting |
| **Security Assumption** | Temporal metadata is accurate; clock drift is bounded |
| **Known Limitation** | Cannot detect real-time race conditions; relies on static temporal evidence |

---

## D3 — Distributed Security Consistency Engine

| Property | Specification |
|:---|:---|
| **Input** | D1/D2 violations, distributed system findings |
| **Output** | `list[DistributedViolation]` — frozen immutable consistency violation objects |
| **Invariants** | Cross-service trust, token propagation, lease consistency, identity drift |
| **Epistemic States** | DISTRIBUTED_VIOLATION / CONSISTENT / UNKNOWN |
| **Mutation Policy** | NONE — read-only, deep-copy immutability verification |
| **Complexity** | O(N × S) where S = number of service boundaries |
| **Security Assumption** | Service boundary definitions are accurate |
| **Known Limitation** | Cannot observe runtime network partitions; relies on static evidence |

---

## D4 — Cross-Batch Correlation Engine

| Property | Specification |
|:---|:---|
| **Input** | D1/D2/D3 violations, C13/C14/C15 graphs, raw findings |
| **Output** | `CrossBatchGraph` — nodes, edges, exploit chains |
| **Invariants** | INV-D4-GRAPH-BOUND-01 (E ≤ 10V), INV-D4-CAUSALITY-01 (correlation ≠ causation) |
| **Epistemic States** | CORRELATED / UNCORRELATED / UNKNOWN |
| **Mutation Policy** | NONE — read-only, deep-copy immutability verification |
| **Complexity** | O(V log V + E log E) |
| **Security Assumption** | `correlation ≠ causation` — shared correlation_id alone does NOT prove causal relationship |
| **Known Limitation** | Edge creation requires typed causal evidence; contextual signals alone are insufficient |

---

## D5 — Evidence-Backed Security Property Reachability Engine

| Property | Specification |
|:---|:---|
| **Input** | `CrossBatchGraph` from D4, raw findings |
| **Output** | `SecurityProofGraph` — reachability verdicts per security property |
| **Invariants** | Evidence sufficiency, counter-evidence weighting, UNKNOWN preservation |
| **Epistemic States** | VULNERABLE / SAFE / UNKNOWN / CONFLICT |
| **Mutation Policy** | NONE — read-only, deep-copy immutability verification |
| **Complexity** | O(V + E) |
| **Security Assumption** | Reachability ≠ exploitability; verdicts represent logical inference, not runtime proof |
| **Known Limitation** | Cannot prove exploit feasibility; only proves evidence-backed reachability |

---

## D6 — Security Decision, Risk Composition & Finding Consolidation Engine

| Property | Specification |
|:---|:---|
| **Input** | `SecurityProofGraph` from D5, raw findings |
| **Output** | `SecurityDecisionGraph` — consolidated, prioritized, deduplicated findings |
| **Invariants** | INV-D6-01 through INV-D6-25, input immutability, epistemic preservation |
| **Epistemic States** | VULNERABLE / SAFE / UNKNOWN / CONFLICT |
| **Mutation Policy** | NONE — read-only, deep-copy immutability verification |
| **Complexity** | O(N log N) |
| **Security Assumption** | Technical Severity and Business Risk are independently computed dimensions |
| **Known Limitation** | Business Risk requires asset/exposure context that may not be available in all analysis modes |

---

## Epistemic State Transition Rules (Global)

These rules apply at **every** boundary (D1→D2, D2→D3, D3→D4, D4→D5, D5→D6):

| Combination | Result |
|:---|:---|
| SAFE + SAFE | SAFE |
| VULNERABLE + VULNERABLE | VULNERABLE |
| UNKNOWN + UNKNOWN | UNKNOWN |
| CONFLICT + anything | CONFLICT |
| SAFE + VULNERABLE | **CONFLICT** |
| SAFE + UNKNOWN | **UNKNOWN** |
| VULNERABLE + UNKNOWN | **UNKNOWN** |

### Forbidden Transitions (Invariant)

| From | To | Status |
|:---|:---|:---|
| UNKNOWN | SAFE | **FORBIDDEN** |
| UNKNOWN | VULNERABLE | **FORBIDDEN** |
| CONFLICT | SAFE | **FORBIDDEN** |
| CONFLICT | VULNERABLE | **FORBIDDEN** |
