# Dependency Analysis: KarsaSec Core Remediation & Verification Subsystem

This document outlines the dependencies and relationships among KarsaSec's key architectural components as identified during the Phase 0 Reconnaissance phase.

## 1. Key Components Identified

*   **`RemediationLifecycleEngine`** (`karsasec/ai/remediation/lifecycle.py`)
    *   **Role**: Orchestrates the 10-stage remediation lifecycle transaction. Connects agents, state machines, snapshoppers, appliers, and verifiers.
    *   **Dependencies**:
        *   `Finding` (`karsasec/core/finding/model.py`)
        *   `SecurityVerdict` (`karsasec/graph/dataflow/security_verdict.py`)
        *   `LifecycleStateMachine` (`karsasec/ai/remediation/state_machine.py`)
        *   `RemediationProvenanceGraph` (`karsasec/ai/remediation/provenance.py`)
        *   `RemediationLedger` (`karsasec/ai/remediation/ledger.py`)
        *   `RemediationAgent` (`karsasec/ai/remediation/agent.py`)
        *   `RemediationApplicationAgent` (`karsasec/ai/remediation/application_agent.py`)
        *   `PatchApprovalToken` (`karsasec/ai/remediation/approval.py`)

*   **`RemediationTransactionPackage`** (`karsasec/ai/remediation/rtp/models.py`)
    *   **Role**: Portable, serialized package representation of the complete transaction history and all commitments, with Zero-Knowledge constraints (no raw source/diff code).
    *   **Dependencies**:
        *   `FindingCommitment`, `EvidenceCommitment`, `RootCauseCommitment`, `StrategyCommitment`, `ProposalCommitment`, `ApprovalCommitment`, `ApplicationCommitment`, `VerificationCommitment`, `ProvenanceCommitment`, `AuditCommitment`.
        *   `compute_canonical_hash` (`karsasec/ai/remediation/rtp/canonical.py`)

*   **`RTPValidator`** (`karsasec/ai/remediation/rtp/validator.py`)
    *   **Role**: Non-bypassable security authority that validates the cryptographic signature / commitments of an RTP and outputs `RTPValidationResult` including `security_verification_status`.
    *   **Dependencies**:
        *   `RemediationTransactionPackage` (`karsasec/ai/remediation/rtp/models.py`)
        *   `RTPValidationResult` (`karsasec/ai/remediation/rtp/models.py`)

*   **`VerificationReceipt`** (`karsasec/ai/remediation/rtp/receipt.py`)
    *   **Role**: Zero-Knowledge Verification Receipt presented to the external API clients.
    *   **Dependencies**:
        *   `RemediationTransactionPackage` (`karsasec/ai/remediation/rtp/models.py`)
        *   `RTPValidationResult` (`karsasec/ai/remediation/rtp/models.py`)
        *   `compute_canonical_hash` (`karsasec/ai/remediation/rtp/canonical.py`)

## 2. Dependency Graph (Mermaid)

```mermaid
graph TD
    subgraph REST API Layer (F1)
        api[remediation.py Router] --> service[RemediationService]
    end

    subgraph Workers Layer (F2)
        worker[WorkerRuntime / CustomWorker] --> service
    end

    subgraph Remediation Subsystem (E13)
        service --> engine[RemediationLifecycleEngine]
        engine --> sm[LifecycleStateMachine]
        engine --> app_agent[RemediationApplicationAgent]
    end

    subgraph RTP Subsystem (F0)
        engine --> rtp_builder[RemediationTransactionPackageBuilder]
        rtp_builder --> rtp[RemediationTransactionPackage]
        rtp_builder --> validator[RTPValidator]
        validator --> validation_result[RTPValidationResult]
        validation_result --> receipt[VerificationReceipt]
    end
```
