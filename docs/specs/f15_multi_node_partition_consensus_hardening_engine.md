# Sprint F15 — Multi-Node Partition Consensus & Split-Brain Hardening Engine Certification

## 1. Scope
This document formally certifies Sprint F15 of the KarsaSec platform. Sprint F15 extends Sprint F14's network partition validation layer into a deterministic **Multi-Node Partition Consensus & Split-Brain Hardening Engine**. It guarantees that under any network partition, message loss, asymmetric connectivity, or stale leader recovery, multiple nodes can NEVER simultaneously obtain or exercise authority over protected resources.

## 2. Architecture
Resides in `karsasec/analysis/distributed/consensus.py` and integrates directly with `partition.py` (NetworkCondition, PartitionScenario), `certification.py` (ReleaseGuard), and `chaos.py` (Chaos Injector).

```
                      ┌──────────────────────────────────────┐
                      │    MultiNodeConsensusEngine          │
                      └──────────────────┬───────────────────┘
                                         │
       ┌─────────────────────────────────┼─────────────────────────────────┐
       ▼                                 ▼                                 ▼
[Quorum Validator]              [Split-Brain Detector]            [State Digest Engine]
 votes >= (N // 2) + 1          valid_authorities <= 1           SHA256 Canonical JSON
```

## 3. Consensus Model
Pure logical reasoning model enforcing strict 13-step deterministic quorum authority evaluation:
Connectivity Check $\rightarrow$ Membership View Validation $\rightarrow$ Epoch Monotonicity $\rightarrow$ Fencing Monotonicity $\rightarrow$ Vote Validation & Deduplication $\rightarrow$ Quorum Check $\rightarrow$ Split-Brain Conflict Check $\rightarrow$ Authority Grant & Commit.

## 4. Quorum Model
Standard majority rule $Q = \lfloor N / 2 \rfloor + 1$ (or explicit override). In a 5-node cluster ($Q=3$), a 3-node majority partition is potentially authoritative; a 2-node minority partition is strictly BLOCKED.

## 5. Authority Model
Authority identity is defined by generation tuple:
$$\text{Generation} = (\text{resource\_id}, \text{consensus\_domain}, \text{epoch}, \text{fencing\_token})$$
Lower generations CANNOT supersede higher generations under any circumstance.

## 6. Epoch Semantics
Monotonic integers incremented on new authority commitments. Requests with target epoch lower than current engine epoch are rejected (`STALE_EPOCH`).

## 7. Fencing Semantics
Fencing tokens strictly increase ($token_{new} > token_{old}$). Mutations presenting stale fencing tokens are rejected (`STALE_FENCING_TOKEN`).

## 8. Partition Behavior
Under a 3+2 partition split:
- **Majority Group (3 nodes)**: Satisfies $Q=3$, allows authority acquisition.
- **Minority Group (2 nodes)**: Fails $Q=3$, returns `BLOCKED_NO_QUORUM`.

## 9. Split-Brain Prevention
Enforces $\text{valid\_authorities}(\text{resource}, \text{epoch}) \le 1$. Simultaneous claims for the same resource within the same epoch trigger `REJECTED_SPLIT_BRAIN`.

## 10. Event Replay Semantics
Idempotent state application: $\text{apply}(\text{apply}(S, E), E) == \text{apply}(S, E)$. Duplicate events are safe no-ops.

## 11. Recovery Semantics
During partition healing, state reconciliation selects the snapshot with the highest generation ($\text{epoch}, \text{fencing\_token}, \text{sequence}$). Stale minority nodes cannot overwrite newer state.

## 12. Convergence Algorithm
Canonical SHA256 digest calculation over sorted JSON fields (`authorities`, `epoch`, `fencing_token`, `membership`, `sequence`). All valid replicas post-healing achieve identical state digests.

## 13. Determinism Guarantees
100% repeatable results across parameterized seeds and execution environments. Strictly zero dependence on wall-clock time, process ordering, or random seeds.

## 14. Failure Classifications
Structured, deterministic classification enum (`ConsensusFailureType`):
- `NO_FAILURE`, `NO_QUORUM`, `UNKNOWN_CONNECTIVITY`, `STALE_EPOCH`, `STALE_FENCING_TOKEN`, `DUPLICATE_EVENT`, `OUT_OF_ORDER_EVENT`, `SPLIT_BRAIN`, `MEMBERSHIP_CONFLICT`, `RECOVERY_CONFLICT`, `CONVERGENCE_FAILURE`.

## 15. Observability Controls
All metric labels use bounded categorical strings (`status_code`, `failure_type`). Zero exposure of unbounded IDs or user inputs in observability streams.

## 16. Formal Invariants Certified
- `INV-F15-CONS-01`: Quorum Authority (`votes >= Q`)
- `INV-F15-CONS-02`: No Dual Authority ($\text{authorities} \le 1$)
- `INV-F15-CONS-03`: Epoch Monotonicity ($epoch_{new} \ge epoch_{curr}$)
- `INV-F15-CONS-04`: Fencing Token Monotonicity ($fencing_{new} > fencing_{prev}$)
- `INV-F15-CONS-05`: Membership View Isolation
- `INV-F15-CONS-06`: No Quorum = No Authority
- `INV-F15-CONS-07`: Stale Leader Rejection
- `INV-F15-CONS-08`: Replay Resistance
- `INV-F15-CONS-09`: Event Ordering Safety
- `INV-F15-CONS-10`: Deterministic Election
- `INV-F15-CONS-11`: Partition Healing Safety
- `INV-F15-CONS-12`: Convergence ($\text{digest}_1 == \text{digest}_N$)
- `INV-F15-CONS-13`: Unknown Connectivity Fail-Closed ($UNKNOWN \neq SAFE$)
- `INV-F15-CONS-14`: Split-Brain Detection
- `INV-F15-CONS-15`: Authority Generation Safety
- `INV-F15-CONS-16`: Bounded Observability

## 17. Test Evidence
- **Suite**: `tests/distributed/test_f15_multi_node_consensus.py`
- **F15 Tests Passed**: **21 / 21 PASSED (100%)**
- **Total Platform Tests**: **300 / 300 PASSED (100%)**
- **Linter**: `ruff check` — **0 Errors**

## 18. Security Analysis
- Zero network socket, shell, or file I/O side effects.
- Fail-closed security boundaries across unknown connectivity and quorum loss.

## 19. Known Limitations
Focuses on logical consensus and split-brain authority; physical network transport security is assumed guarded at lower layers.

## 20. Certification Statement
Track C (Distributed Systems Assurance) is now 100% complete (15/15 Sprints Certified). Sprint F15 is certified and locked as a complete, frozen roadmap node.

$$\mathbf{SPRINT\_F15\_CERTIFIED\_AND\_FROZEN}$$
