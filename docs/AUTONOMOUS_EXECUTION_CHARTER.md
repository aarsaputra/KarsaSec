# KARSASEC AUTONOMOUS EXECUTION CHARTER

## Program-Driven Execution Protocol for AI Software Security Engineer

### Version 1.0

---

## 1. Execution Principle
The AI Agent operates strictly under the Single Source of Truth defined in [`PROGRAM_EXECUTION_SPEC.md`](PROGRAM_EXECUTION_SPEC.md).

The AI Agent MUST NOT prompt the human operator for approval after completing individual sprints.

The AI Agent MUST automatically advance to the next dependent node in the Fixed Roadmap DAG until `KARSASEC_PLATFORM_CERTIFIED` is reached.

---

## 2. Active Execution Sequence

```text
[CURRENT ACTIVE PIPELINE]

Track B: K1.7 (CERTIFIED & FROZEN)
Track C: F12  (CERTIFIED & FROZEN)
   │
   ▼
Sprint F13 (Chaos Engineering Framework) ────────► [IN PROGRESS]
   │
   ▼
Sprint F14 (Network Partition Validation)
   │
   ▼
Sprint F15 (Disaster Recovery Certification)
   │
   ▼
Sprint D3  (Hardcoding & Dataflow Leakage Scan)
   │
   ▼
Sprint D4  (Red Team Dynamic Attack Framework)
   │
   ▼
Sprint E3  (Multi-Tenant Isolation Enforcement)
   │
   ▼
Sprint E4  (Compliance Reporting & SARIF Engine)
   │
   ▼
Sprint A8  (Hybrid Symbolic Analysis & Path Conditions)
   │
   ▼
[KARSASEC_PLATFORM_CERTIFIED & PROGRAM TERMINATION]
```

---

## 3. Strict Execution Protocol per Node
For every node `S_i` in the execution DAG:
1. **Validate Preconditions**: Verify that all `depends_on` nodes are `CERTIFIED`.
2. **Implement Production Code**: Write clean, type-hinted code fulfilling sprint requirements.
3. **Implement Test Suite**: Create unit and adversarial tests covering all formal invariants.
4. **Execute Verification**: Run pytest and ruff across the repository.
5. **Emit Audit Document**: Write standard documentation artifact in `docs/`.
6. **Lock Sprint State**: Record `status: CERTIFIED` and set `locked: true`.
7. **Advance Node**: Automatically move to `S_{i+1}` in the DAG. DO NOT generate sub-sprints.

---

## 4. Hard Stop Condition
Execution MUST terminate when `A8_CERTIFIED`, `K1.7_CERTIFICATION_BOUNDARY_COVERAGE_CERTIFIED`, `F15_CERTIFIED`, `D4_CERTIFIED`, and `E4_CERTIFIED` are all `PASS`.

Emit final verdict:

$$\mathbf{KARSASEC\_PLATFORM\_CERTIFIED}$$
