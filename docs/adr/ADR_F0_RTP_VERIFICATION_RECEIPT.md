# ADR-F0: Remediation Transaction Package (RTP) & Verification Receipt Architecture

* **Status**: Accepted
* **Deciders**: KarsaSec Engineering Team
* **Date**: 2026-08-13

---

## Context and Problem Statement

As KarsaSec transitions into Sprint F (Platform & Enterprise Integration), enterprise customers require a verifiable, auditable record of AI-assisted vulnerability remediations. However, enterprise privacy policies strictly forbid sending raw source code, unified diff hunks, or credentials to external audit systems or centralized SaaS platforms.

How do we design a zero-knowledge, cryptographically bound transaction receipt for AI remediations that guarantees security rescan verification without leaking proprietary source code?

---

## Decision Drivers

1. **Privacy & Zero Code Exposure**: Raw source code, diff hunks, and secrets MUST NOT leak into transaction receipts or enterprise export packages.
2. **Deterministic Cryptographic Integrity**: All transaction fingerprints must be SHA-256 hashes generated from canonicalized RFC 8785 JSON payloads.
3. **Zero LLM Authority**: LLM claims must carry 0 authority. Security verification status MUST be derived solely from deterministic SAST rescans showing 0 matching findings.
4. **Side-Effect-Free Operations**: Package construction and verification must be read-only with zero process or filesystem side-effects.

---

## Decision Outcome

We decided to implement the **Remediation Transaction Package (RTP)** and **Verification Receipt** architecture (`karsasec.ai.remediation.rtp`) in Sprint F0.

### Key Components

1. **`RemediationTransactionPackage`**: Immutable payload encapsulating 9 privacy-safe commitments (`FindingCommitment`, `EvidenceCommitment`, `RootCauseCommitment`, `StrategyCommitment`, `ProposalCommitment`, `ApprovalCommitment`, `ApplicationCommitment`, `VerificationCommitment`, `ProvenanceCommitment`, `AuditCommitment`).
2. **`VerificationReceipt`**: Portable, signable verification receipt containing high-level transaction commitments and cryptographic fingerprints.
3. **`RTPValidator`**: 9-stage validation pipeline separating structural integrity (`IntegrityStatus.VALID` / `INVALID`) from security verification (`SecurityVerificationStatus.SECURITY_VERIFIED` / `SECURITY_NOT_VERIFIED`).
4. **Payload Privacy Guard**: Deserialization (`import_rtp`) automatically rejects payloads containing sensitive keys (`source_code`, `diff`, `password`, `secret`, `api_key`, etc.) with `RTPPrivacyError`.

---

## Consequences

### Positive
- Enterprise customers can store or transmit RTP receipts to compliance auditors with 0 risk of IP or credential leakage.
- Cryptographic verification guarantees tampering detection across proposals, approvals, snapshots, and rescan outputs.
- Fully compatible with future enterprise REST API endpoints (Sprint F1) via OpenAPI 3.1 schema definitions.

### Negative
- Raw diffs cannot be reconstructed directly from RTP receipts; auditors must rely on the underlying local git repository and snapshot SHA-256 hashes for raw code inspection.
