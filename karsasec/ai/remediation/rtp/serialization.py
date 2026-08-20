"""Deterministic Serialization Engine & OpenAPI 3.1 Schema Generator (Sprint F0).

Provides round-trip JSON export/import functions for RemediationTransactionPackage (RTP)
and generates OpenAPI 3.1-compatible JSON schema definitions for future F1 platform endpoints.

Enforces Security Invariants:
  - R1-R6: Deterministic Serialization Round-Trip Guarantee.
  - Zero execution capability (Pure data transformations).
"""

from __future__ import annotations

import json
from typing import Any

from karsasec.ai.remediation.rtp.canonical import canonicalize
from karsasec.ai.remediation.rtp.errors import RTPPrivacyError, RTPSerializationError
from karsasec.ai.remediation.rtp.validator import _contains_prohibited_privacy_data
from karsasec.ai.remediation.rtp.models import (
    ApprovalCommitment,
    ApplicationCommitment,
    AuditCommitment,
    EvidenceCommitment,
    FindingCommitment,
    ProposalCommitment,
    ProvenanceCommitment,
    RTP_SCHEMA_NAME,
    RTP_SCHEMA_VERSION,
    RemediationTransactionPackage,
    RootCauseCommitment,
    StrategyCommitment,
    VerificationCommitment,
)


def export_rtp(rtp: RemediationTransactionPackage) -> str:
    """Exports an RTP object to a deterministic canonical UTF-8 JSON string."""
    return canonicalize(rtp.to_dict()).decode("utf-8")


def import_rtp(data: str | bytes | dict[str, Any]) -> RemediationTransactionPackage:
    """Imports a JSON string, bytes, or dictionary into an immutable RemediationTransactionPackage."""
    if isinstance(data, (str, bytes)):
        try:
            d = json.loads(data)
        except Exception as err:
            raise RTPSerializationError(f"Malformed JSON payload: {err}") from err
    elif isinstance(data, dict):
        d = data
    else:
        raise RTPSerializationError(f"Unsupported import type: '{type(data).__name__}'")

    if not isinstance(d, dict):
        raise RTPSerializationError("RTP JSON payload must resolve to a JSON dictionary object")

    privacy_err = _contains_prohibited_privacy_data(d)
    if privacy_err:
        raise RTPPrivacyError(f"Privacy boundary violation in payload: {privacy_err}")

    try:
        schema_name = d.get("schema_name", RTP_SCHEMA_NAME)
        schema_version = d.get("schema_version", RTP_SCHEMA_VERSION)
        tx_id = d["transaction_id"]
        repo_id = d["repository_identity"]
        created_at = d["created_at"]
        status = d["status"]

        f_raw = d["finding"]
        finding = FindingCommitment(
            finding_id=f_raw["finding_id"],
            rule_id=f_raw["rule_id"],
            severity=f_raw["severity"],
            cwe=f_raw["cwe"],
            file_path=f_raw["file_path"],
            line_number=int(f_raw["line_number"]),
            finding_fingerprint=f_raw["finding_fingerprint"],
        )

        evidence: EvidenceCommitment | None = None
        if d.get("evidence"):
            ev_raw = d["evidence"]
            evidence = EvidenceCommitment(
                evidence_count=int(ev_raw["evidence_count"]),
                evidence_fingerprint=ev_raw["evidence_fingerprint"],
            )

        root_cause: RootCauseCommitment | None = None
        if d.get("root_cause"):
            rca_raw = d["root_cause"]
            root_cause = RootCauseCommitment(
                rca_category=rca_raw["rca_category"],
                confidence=float(rca_raw["confidence"]),
                rca_fingerprint=rca_raw["rca_fingerprint"],
            )

        strategy: StrategyCommitment | None = None
        if d.get("strategy"):
            st_raw = d["strategy"]
            strategy = StrategyCommitment(
                strategy_type=st_raw["strategy_type"],
                target_file=st_raw["target_file"],
                strategy_fingerprint=st_raw["strategy_fingerprint"],
            )

        proposal: ProposalCommitment | None = None
        if d.get("proposal"):
            pr_raw = d["proposal"]
            proposal = ProposalCommitment(
                proposal_id=pr_raw["proposal_id"],
                risk_level=pr_raw["risk_level"],
                target_files=tuple(pr_raw["target_files"]),
                proposal_fingerprint=pr_raw["proposal_fingerprint"],
            )

        approval: ApprovalCommitment | None = None
        if d.get("approval"):
            ap_raw = d["approval"]
            approval = ApprovalCommitment(
                approval_token_id=ap_raw["approval_token_id"],
                approver=ap_raw["approver"],
                approval_status=ap_raw["approval_status"],
                approval_fingerprint=ap_raw["approval_fingerprint"],
            )

        application: ApplicationCommitment | None = None
        if d.get("application"):
            app_raw = d["application"]
            application = ApplicationCommitment(
                source_snapshot_hash=app_raw["source_snapshot_hash"],
                post_apply_snapshot_hash=app_raw["post_apply_snapshot_hash"],
                application_status=app_raw["application_status"],
            )

        verification: VerificationCommitment | None = None
        if d.get("verification"):
            v_raw = d["verification"]
            verification = VerificationCommitment(
                verification_run_id=v_raw["verification_run_id"],
                status=v_raw["status"],
                matching_findings_count=int(v_raw["matching_findings_count"]),
                verification_fingerprint=v_raw["verification_fingerprint"],
            )

        prov_raw = d["provenance"]
        provenance = ProvenanceCommitment(graph_fingerprint=prov_raw["graph_fingerprint"])

        aud_raw = d["audit"]
        audit = AuditCommitment(ledger_fingerprint=aud_raw["ledger_fingerprint"])

        receipt_fp = d["receipt_fingerprint"]

        return RemediationTransactionPackage(
            schema_name=schema_name,
            schema_version=schema_version,
            transaction_id=tx_id,
            repository_identity=repo_id,
            created_at=created_at,
            status=status,
            finding=finding,
            evidence=evidence,
            root_cause=root_cause,
            strategy=strategy,
            proposal=proposal,
            approval=approval,
            application=application,
            verification=verification,
            provenance=provenance,
            audit=audit,
            receipt_fingerprint=receipt_fp,
        )
    except KeyError as missing_key:
        raise RTPSerializationError(f"Missing required RTP dictionary key: {missing_key}") from missing_key
    except Exception as err:
        raise RTPSerializationError(f"Failed to deserialize RTP dictionary: {err}") from err


def generate_rtp_openapi_schema() -> dict[str, Any]:
    """Generates an OpenAPI 3.1-compatible JSON schema definition for RTP contract artifacts."""
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "KarsaSec Remediation Transaction Package (RTP) Contract API Schema",
            "version": "1.0.0",
            "description": "Cryptographic contract boundary for verifiable AI remediation transactions.",
        },
        "components": {
            "schemas": {
                "RemediationTransactionPackage": {
                    "type": "object",
                    "required": [
                        "schema_name",
                        "schema_version",
                        "transaction_id",
                        "repository_identity",
                        "created_at",
                        "status",
                        "finding",
                        "provenance",
                        "audit",
                        "receipt_fingerprint",
                    ],
                    "properties": {
                        "schema_name": {"type": "string", "example": "karsasec-remediation-transaction"},
                        "schema_version": {"type": "string", "example": "1.0"},
                        "transaction_id": {"type": "string", "example": "RTP-a1b2c3d4"},
                        "repository_identity": {"type": "string", "example": "repo:org/project"},
                        "created_at": {"type": "string", "format": "date-time"},
                        "status": {"type": "string", "example": "VERIFIED_FIXED"},
                        "finding": {"$ref": "#/components/schemas/FindingCommitment"},
                        "evidence": {"$ref": "#/components/schemas/EvidenceCommitment"},
                        "root_cause": {"$ref": "#/components/schemas/RootCauseCommitment"},
                        "strategy": {"$ref": "#/components/schemas/StrategyCommitment"},
                        "proposal": {"$ref": "#/components/schemas/ProposalCommitment"},
                        "approval": {"$ref": "#/components/schemas/ApprovalCommitment"},
                        "application": {"$ref": "#/components/schemas/ApplicationCommitment"},
                        "verification": {"$ref": "#/components/schemas/VerificationCommitment"},
                        "provenance": {"$ref": "#/components/schemas/ProvenanceCommitment"},
                        "audit": {"$ref": "#/components/schemas/AuditCommitment"},
                        "receipt_fingerprint": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                    },
                },
                "VerificationReceipt": {
                    "type": "object",
                    "required": [
                        "receipt_version",
                        "receipt_id",
                        "transaction_id",
                        "repository_identity",
                        "finding_id",
                        "rule_id",
                        "provenance_fingerprint",
                        "ledger_fingerprint",
                        "integrity_status",
                        "security_verification_status",
                        "matching_findings_count",
                        "receipt_fingerprint",
                    ],
                    "properties": {
                        "receipt_version": {"type": "string", "example": "1.0"},
                        "receipt_id": {"type": "string", "example": "RCP-x1y2z3"},
                        "transaction_id": {"type": "string", "example": "RTP-a1b2c3d4"},
                        "repository_identity": {"type": "string", "example": "repo:org/project"},
                        "finding_id": {"type": "string", "example": "F-001"},
                        "rule_id": {"type": "string", "example": "KS-PY-SQL-001"},
                        "proposal_fingerprint": {"type": "string"},
                        "approval_token_id": {"type": "string"},
                        "source_snapshot_hash": {"type": "string"},
                        "post_apply_snapshot_hash": {"type": "string"},
                        "verification_run_id": {"type": "string"},
                        "verification_fingerprint": {"type": "string"},
                        "provenance_fingerprint": {"type": "string"},
                        "ledger_fingerprint": {"type": "string"},
                        "integrity_status": {"type": "string", "enum": ["VALID", "INVALID"]},
                        "security_verification_status": {
                            "type": "string",
                            "enum": ["SECURITY_VERIFIED", "SECURITY_NOT_VERIFIED"],
                        },
                        "matching_findings_count": {"type": "integer", "minimum": 0},
                        "receipt_fingerprint": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                    },
                },
                "RTPValidationResult": {
                    "type": "object",
                    "required": [
                        "is_valid",
                        "integrity_status",
                        "security_verification_status",
                        "errors",
                        "warnings",
                    ],
                    "properties": {
                        "is_valid": {"type": "boolean"},
                        "integrity_status": {"type": "string", "enum": ["VALID", "INVALID"]},
                        "security_verification_status": {
                            "type": "string",
                            "enum": ["SECURITY_VERIFIED", "SECURITY_NOT_VERIFIED"],
                        },
                        "errors": {"type": "array", "items": {"type": "string"}},
                        "warnings": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "FindingCommitment": {
                    "type": "object",
                    "required": [
                        "finding_id",
                        "rule_id",
                        "severity",
                        "cwe",
                        "file_path",
                        "line_number",
                        "finding_fingerprint",
                    ],
                    "properties": {
                        "finding_id": {"type": "string"},
                        "rule_id": {"type": "string"},
                        "severity": {"type": "string"},
                        "cwe": {"type": "string"},
                        "file_path": {"type": "string"},
                        "line_number": {"type": "integer"},
                        "finding_fingerprint": {"type": "string"},
                    },
                },
                "EvidenceCommitment": {
                    "type": "object",
                    "required": ["evidence_count", "evidence_fingerprint"],
                    "properties": {
                        "evidence_count": {"type": "integer"},
                        "evidence_fingerprint": {"type": "string"},
                    },
                },
                "RootCauseCommitment": {
                    "type": "object",
                    "required": ["rca_category", "confidence", "rca_fingerprint"],
                    "properties": {
                        "rca_category": {"type": "string"},
                        "confidence": {"type": "number"},
                        "rca_fingerprint": {"type": "string"},
                    },
                },
                "StrategyCommitment": {
                    "type": "object",
                    "required": ["strategy_type", "target_file", "strategy_fingerprint"],
                    "properties": {
                        "strategy_type": {"type": "string"},
                        "target_file": {"type": "string"},
                        "strategy_fingerprint": {"type": "string"},
                    },
                },
                "ProposalCommitment": {
                    "type": "object",
                    "required": ["proposal_id", "risk_level", "target_files", "proposal_fingerprint"],
                    "properties": {
                        "proposal_id": {"type": "string"},
                        "risk_level": {"type": "string"},
                        "target_files": {"type": "array", "items": {"type": "string"}},
                        "proposal_fingerprint": {"type": "string"},
                    },
                },
                "ApprovalCommitment": {
                    "type": "object",
                    "required": ["approval_token_id", "approver", "approval_status", "approval_fingerprint"],
                    "properties": {
                        "approval_token_id": {"type": "string"},
                        "approver": {"type": "string"},
                        "approval_status": {"type": "string"},
                        "approval_fingerprint": {"type": "string"},
                    },
                },
                "ApplicationCommitment": {
                    "type": "object",
                    "required": ["source_snapshot_hash", "post_apply_snapshot_hash", "application_status"],
                    "properties": {
                        "source_snapshot_hash": {"type": "string"},
                        "post_apply_snapshot_hash": {"type": "string"},
                        "application_status": {"type": "string"},
                    },
                },
                "VerificationCommitment": {
                    "type": "object",
                    "required": [
                        "verification_run_id",
                        "status",
                        "matching_findings_count",
                        "verification_fingerprint",
                    ],
                    "properties": {
                        "verification_run_id": {"type": "string"},
                        "status": {"type": "string"},
                        "matching_findings_count": {"type": "integer"},
                        "verification_fingerprint": {"type": "string"},
                    },
                },
                "ProvenanceCommitment": {
                    "type": "object",
                    "required": ["graph_fingerprint"],
                    "properties": {
                        "graph_fingerprint": {"type": "string"},
                    },
                },
                "AuditCommitment": {
                    "type": "object",
                    "required": ["ledger_fingerprint"],
                    "properties": {
                        "ledger_fingerprint": {"type": "string"},
                    },
                },
            }
        },
    }
