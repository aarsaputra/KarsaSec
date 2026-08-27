# Sprint E16 — Enforcement Engine & Release State Machine

## Anti-Confused-Deputy Enforcement Engine
The `EnforcementEngine` (`karsasec/analysis/e16_enforcement.py`) rejects bare boolean input parameters (`approved=True`) to prevent confused-deputy authorization bypasses. Operational permissions MUST derive from a validated `ReleaseAdmission` instance.

### Permission Mapping
- `APPROVED` $\rightarrow$ `PERMITTED` (`is_permitted=True`)
- `BLOCKED` $\rightarrow$ `PROHIBITED_BLOCKED` (`is_permitted=False`)
- `REVIEW_REQUIRED` $\rightarrow$ `PROHIBITED_REVIEW_REQUIRED` (`is_permitted=False`)
- `UNKNOWN` $\rightarrow$ `PROHIBITED_UNKNOWN` (`is_permitted=False`)

## Monotonic Release State Machine
The `ReleaseStateMachine` (`karsasec/analysis/e16_release.py`) enforces valid lifecycle transitions:
```text
CREATED -> SECURITY_EVALUATED -> (APPROVED | REVIEW_REQUIRED | BLOCKED | UNKNOWN)
```

### Forbidden Direct Transitions
- `BLOCKED` $\rightarrow$ `APPROVED` (REJECTED)
- `UNKNOWN` $\rightarrow$ `APPROVED` (REJECTED)
- `REVIEW_REQUIRED` $\rightarrow$ `APPROVED` (REJECTED)

Re-evaluating a security-failed artifact requires resetting the state machine with a new, distinct `evaluation_id`.
