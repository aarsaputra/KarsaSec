"""Data models for KarsaSec Insecure Destructive Actions & Impact Capability Engine (Batch C11)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class DestructiveCategory(StrEnum):
    DESTRUCTIVE_FILE_DELETE = "DESTRUCTIVE_FILE_DELETE"
    DESTRUCTIVE_DIRECTORY_DELETE = "DESTRUCTIVE_DIRECTORY_DELETE"
    DATABASE_DESTRUCTION = "DATABASE_DESTRUCTION"
    QUEUE_PURGE = "QUEUE_PURGE"
    CACHE_FLUSH = "CACHE_FLUSH"
    OBJECT_STORAGE_DELETE = "OBJECT_STORAGE_DELETE"
    BACKUP_DELETION = "BACKUP_DELETION"
    PROCESS_TERMINATION = "PROCESS_TERMINATION"
    SERVICE_SHUTDOWN = "SERVICE_SHUTDOWN"
    TENANT_WIPE = "TENANT_WIPE"
    BULK_DELETE_OPERATION = "BULK_DELETE_OPERATION"
    MASS_UPDATE_OPERATION = "MASS_UPDATE_OPERATION"
    AVAILABILITY_IMPACT = "AVAILABILITY_IMPACT"


class OperationType(StrEnum):
    DROP_TABLE = "DROP_TABLE"
    DROP_DATABASE = "DROP_DATABASE"
    TRUNCATE_TABLE = "TRUNCATE_TABLE"
    DELETE_FROM = "DELETE_FROM"
    REMOVE_FILE = "REMOVE_FILE"
    REMOVE_DIR = "REMOVE_DIR"
    PURGE_QUEUE = "PURGE_QUEUE"
    FLUSH_CACHE = "FLUSH_CACHE"
    DELETE_BUCKET = "DELETE_BUCKET"
    DELETE_OBJECT = "DELETE_OBJECT"
    KILL_PROCESS = "KILL_PROCESS"
    SHUTDOWN_SERVICE = "SHUTDOWN_SERVICE"
    MASS_UPDATE = "MASS_UPDATE"


@dataclass
class CapabilityImpactGraph:
    """Graph representation of Exploit Primitive -> Destructive Capability -> Business Impact (INV-C11-03)."""

    primitive: str  # e.g., IDOR, SSRF, COMMAND_INJECTION, SSTI, UNCHECKED_ENDPOINT
    capability: str  # e.g., DATABASE_DESTRUCTION, DIRECTORY_DELETE, CLUSTER_DELETE
    business_impact: str  # e.g., TENANT_WIPE, AVAILABILITY_IMPACT, DATA_LOSS
    evidence_chain: list[str] = field(default_factory=list)


@dataclass
class DestructiveContext:
    """Context node passed into DestructiveActionsReasoningEngine."""

    source_kind: str  # HTTP_REQUEST, ADMIN_API, BACKGROUND_JOB, SSRF_CALLBACK
    source_symbol: str
    operation_type: OperationType | str
    target_resource: str
    is_authorization_verified: bool = False
    is_tenant_scoped: bool = False
    is_user_controlled: bool = True
    root_cause: str = "UNAUTHORIZED_ACCESS"  # IDOR, SSRF, COMMAND_INJECTION, SSTI, MISSING_AUTHZ
    framework_resolver_valid: bool | None = True  # True, False, None (UNKNOWN)
    language: str = "python"


@dataclass
class DestructiveEvidence:
    """Machine-readable evidence output for Destructive Actions findings."""

    category: DestructiveCategory
    root_cause: str
    impact: str
    source_kind: str
    source_symbol: str
    operation: dict[str, Any]
    authorization: dict[str, bool]
    impact_graph: dict[str, Any] | None = None
    evidence_path: list[str] = field(default_factory=list)
    resolution: str = "VULNERABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "root_cause": self.root_cause,
            "impact": self.impact,
            "source": {
                "kind": self.source_kind,
                "symbol": self.source_symbol,
            },
            "operation": self.operation,
            "authorization": self.authorization,
            "impact_graph": self.impact_graph,
            "evidence_path": self.evidence_path,
            "resolution": self.resolution,
        }
