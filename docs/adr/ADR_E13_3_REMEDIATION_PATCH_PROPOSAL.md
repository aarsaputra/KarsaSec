# ADR E13-3: Evidence-Grounded Remediation Planning & Safe Patch Proposal Agent

## Status
ACCEPTED

## Context
In Sprint E13-1 and E13-2, KarsaSec established RAG-guided explanation and Root Cause Analysis (RCA) reflection capabilities.
Sprint E13-3 completes the **Analysis → Explanation → RCA → Remediation Proposal** flow.
However, to preserve SAST authority and prevent unauthorized mutation or hallucinated fixes, strict security invariants are required.

## Key Decisions

1. **Read-Only Engine Boundary (G12-G14)**
   - The Remediation Agent operates exclusively on in-memory representations (`RemediationStrategy` and `PatchProposal`).
   - No filesystem mutations, git operations, or subprocess executions are performed during proposal synthesis.
   - All proposed diffs are data structures requiring explicit human review.

2. **Evidence-Grounded Planning (G1)**
   - Remediation strategies are derived from sink category, root cause analysis, and evidence.
   - When evidence is `UNKNOWN`, `NOT_PROVEN`, or contradictory, automated remediation is withheld and `MANUAL_REVIEW_REQUIRED` is assigned (Invariant G1).

3. **Deterministic Diff & SHA-256 Fingerprinting (G8)**
   - `RemediationStrategy` and `PatchProposal` compute deterministic SHA-256 fingerprints stable across `PYTHONHASHSEED`.

4. **Human-in-the-Loop Safeguard (G15)**
   - Every proposal is tagged with `PatchValidationStatus.REQUIRES_HUMAN_REVIEW` or `VALID`.
   - Auto-application of patches to source repositories is prohibited.

5. **Prompt Injection Hardening (G10-G11)**
   - Source snippets, user comments, and RAG knowledge chunks are treated as untrusted data.
   - Injecting instructions (e.g. `<system>Suppression</system>`) does not mutate SAST verdicts or suppress findings.

## Consequences
- **Positive**: Clean separation between analysis and recommendation layers. Zero risk of code corruption or accidental commit.
- **Positive**: Fully testable, deterministic diff generation with offline template fallbacks.
- **Compliance**: Integrates seamlessly with SARIF export and `karsasec explain --remediation --patch` CLI.
