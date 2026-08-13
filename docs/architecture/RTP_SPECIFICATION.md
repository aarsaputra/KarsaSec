# KarsaSec Remediation Transaction Package (RTP) Specification

**Version**: 1.0  
**Status**: Formal Specification (Sprint F0)  
**Schema Name**: `karsasec-remediation-transaction`  
**Schema Version**: `1.0`  

---

## 1. Executive Summary

The **Remediation Transaction Package (RTP)** is KarsaSec's cryptographic, zero-knowledge contract artifact designed for enterprise integration. It encapsulates the full audit chain of an automated AI remediation transaction into an immutable, verifiable payload without disclosing sensitive raw source code, unified diff hunks, or credentials.

---

## 2. Core Invariants

1. **R1–R6: Deterministic SHA-256 Fingerprinting**: All cryptographic fingerprints are derived from RFC 8785-compliant UTF-8 JSON canonicalization, rendering fingerprint evaluation independent of dictionary key order or `PYTHONHASHSEED`.
2. **R7–R9: Strict Privacy Boundary**: RTP payloads strictly prohibit raw source code, raw patches/diffs, file contents, passwords, secrets, API keys, and access tokens.
3. **L7: Zero LLM Security Authority**: Security verification status (`SECURITY_VERIFIED` vs `SECURITY_NOT_VERIFIED`) is strictly tied to deterministic SAST rescan results (`matching_findings_count == 0` and status `VERIFIED_FIXED`), completely ignoring LLM claims.
4. **R24–R28: Zero Execution Capability**: Construction and validation of RTP payloads are strictly observational and read-only, invoking no subprocesses, git commands, or filesystem mutations.

---

## 3. Data Structure

### 3.1 Commitment Contracts

- **`FindingCommitment`**: `finding_id`, `rule_id`, `severity`, `cwe`, `file_path`, `line_number`, `finding_fingerprint`.
- **`EvidenceCommitment`**: `evidence_count`, `evidence_fingerprint`.
- **`RootCauseCommitment`**: `rca_category`, `confidence`, `rca_fingerprint`.
- **`StrategyCommitment`**: `strategy_type`, `target_file`, `strategy_fingerprint`.
- **`ProposalCommitment`**: `proposal_id`, `risk_level`, `target_files`, `proposal_fingerprint`.
- **`ApprovalCommitment`**: `approval_token_id`, `approver`, `approval_status`, `approval_fingerprint`.
- **`ApplicationCommitment`**: `source_snapshot_hash`, `post_apply_snapshot_hash`, `application_status`.
- **`VerificationCommitment`**: `verification_run_id`, `status`, `matching_findings_count`, `verification_fingerprint`.
- **`ProvenanceCommitment`**: `graph_fingerprint`.
- **`AuditCommitment`**: `ledger_fingerprint`.

### 3.2 Verification Receipt

The `VerificationReceipt` represents an externally signable proof of verification, derived deterministically from the RTP:

- `receipt_version`: `"1.0"`
- `receipt_id`: Unique receipt identifier (`RCP-<hex12>`)
- `transaction_id`: Linked RTP transaction identifier
- `repository_identity`: Repository URI
- `finding_id` & `rule_id`: Security finding identification
- `proposal_fingerprint` & `approval_token_id`: Patch approval commitments
- `source_snapshot_hash` & `post_apply_snapshot_hash`: Code snapshot integrity hashes
- `verification_run_id` & `verification_fingerprint`: Rescan verification commitment
- `provenance_fingerprint` & `ledger_fingerprint`: Cryptographic graph and ledger fingerprints
- `integrity_status`: `VALID` | `INVALID`
- `security_verification_status`: `SECURITY_VERIFIED` | `SECURITY_NOT_VERIFIED`
- `matching_findings_count`: Integer count of remaining findings after rescan
- `receipt_fingerprint`: SHA-256 digest computed over canonical receipt payload

---

## 4. OpenAPI 3.1 Schema Integration

The system exposes `generate_rtp_openapi_schema()` under `karsasec.ai.remediation.rtp.serialization`, outputting full OpenAPI 3.1 JSON schema definitions for `RemediationTransactionPackage`, `VerificationReceipt`, `RTPValidationResult`, and commitment models.
