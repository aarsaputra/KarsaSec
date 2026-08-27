# Sprint E16 — Release Admission Engine

## Overview
The `ReleaseAdmissionEngine` (`karsasec/analysis/e16_admission.py`) serves as the deterministic release decision generator.

## Signature & Interface
```python
def evaluate(
    self,
    artifact: ReleaseArtifact | None,
    decision: SecurityDecision | None,
    policy: EnforcementPolicy | None = None,
    remediation_plan: Any | None = None,
    regression_report: Any | None = None,
) -> ReleaseAdmission
```

## Guarantees
- Zero side-effects (no network, no subprocess, no shell, no cloud calls).
- Returns an immutable `ReleaseAdmission` object bound by SHA-256 canonical identity (`E16-ADMISSION:v1:`).
- Strictly preserves replay protection and TOCTOU artifact content binding.
