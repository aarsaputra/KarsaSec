"""Insecure Destructive Actions & Impact Capability Reasoning Engine for Batch C11."""

from __future__ import annotations

from karsasec.analysis.destructive.models import (
    CapabilityImpactGraph,
    DestructiveCategory,
    DestructiveContext,
    DestructiveEvidence,
    OperationType,
)


class DestructiveActionsReasoningEngine:
    """Deterministic reasoning engine for Insecure Destructive Actions, Tenant Wipes, and Operational Impact Capabilities."""

    def evaluate_destructive_action(self, ctx: DestructiveContext) -> DestructiveEvidence | None:
        """Evaluates destructive action context, authorization verification, tenant scoping, and impact capability graph."""
        # Step 1: INV-C11-01 (Destructive Action != Vulnerability)
        # If operation is fully authorized AND properly tenant-scoped -> SAFE
        if ctx.is_authorization_verified and ctx.is_tenant_scoped and ctx.is_user_controlled is False:
            return DestructiveEvidence(
                category=DestructiveCategory.DESTRUCTIVE_FILE_DELETE,
                root_cause=ctx.root_cause,
                impact="NONE",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                operation={"type": str(ctx.operation_type), "target": ctx.target_resource},
                authorization={"verified": True, "tenant_scoped": True},
                evidence_path=[ctx.source_kind, ctx.source_symbol, "authorized_operation"],
                resolution="SAFE",
            )

        # Step 2: Unresolved framework authorization state -> UNKNOWN (INV-GLOBAL-01)
        if ctx.framework_resolver_valid is False:
            return DestructiveEvidence(
                category=DestructiveCategory.DESTRUCTIVE_FILE_DELETE,
                root_cause="UNRESOLVED_FRAMEWORK_STATE",
                impact="UNKNOWN",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                operation={"type": str(ctx.operation_type), "target": ctx.target_resource},
                authorization={"verified": False, "tenant_scoped": False},
                evidence_path=[ctx.source_kind, ctx.source_symbol, "unresolved_authz_state"],
                resolution="UNKNOWN",
            )

        op_str = str(ctx.operation_type).upper()

        # Step 3: Multi-Tenant Wipe Evaluation (INV-C11-02 Root Cause vs Impact)
        if (not ctx.is_tenant_scoped and not ctx.is_authorization_verified) and ("TENANT" in ctx.target_resource.upper() or ctx.operation_type == "TENANT_WIPE"):
            graph = CapabilityImpactGraph(
                primitive=ctx.root_cause,
                capability="UNSCOPED_MULTI_TENANT_DELETE",
                business_impact="TENANT_WIPE",
                evidence_chain=[ctx.source_kind, ctx.source_symbol, "DELETE_ENDPOINT", op_str],
            )
            return DestructiveEvidence(
                category=DestructiveCategory.TENANT_WIPE,
                root_cause=ctx.root_cause,
                impact="TENANT_WIPE",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                operation={"type": op_str, "target": ctx.target_resource},
                authorization={"verified": ctx.is_authorization_verified, "tenant_scoped": False},
                impact_graph={
                    "primitive": graph.primitive,
                    "capability": graph.capability,
                    "business_impact": graph.business_impact,
                },
                evidence_path=graph.evidence_chain,
                resolution="VULNERABLE",
            )

        # Step 4: Database Destruction (DROP, TRUNCATE, DELETE_FROM)
        if op_str in (OperationType.DROP_DATABASE.value, OperationType.DROP_TABLE.value, OperationType.TRUNCATE_TABLE.value, OperationType.DELETE_FROM.value) or "DROP" in op_str or "TRUNCATE" in op_str:
            graph = CapabilityImpactGraph(
                primitive=ctx.root_cause,
                capability="DATABASE_MUTATION",
                business_impact="DATA_LOSS",
                evidence_chain=[ctx.source_kind, ctx.source_symbol, "SQL_EXECUTION", op_str],
            )
            return DestructiveEvidence(
                category=DestructiveCategory.DATABASE_DESTRUCTION,
                root_cause=ctx.root_cause,
                impact="DATABASE_DESTRUCTION",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                operation={"type": op_str, "target": ctx.target_resource},
                authorization={"verified": ctx.is_authorization_verified, "tenant_scoped": ctx.is_tenant_scoped},
                impact_graph={
                    "primitive": graph.primitive,
                    "capability": graph.capability,
                    "business_impact": graph.business_impact,
                },
                evidence_path=graph.evidence_chain,
                resolution="VULNERABLE",
            )

        # Step 5: Directory Destruction (rm -rf / rmtree)
        if op_str in (OperationType.REMOVE_DIR.value, "RMDIR", "RM_RF", "SHUTIL_RMTREE") or "RECURSIVE_DELETE" in op_str or "RM_RF" in op_str:
            graph = CapabilityImpactGraph(
                primitive=ctx.root_cause,
                capability="RECURSIVE_FILESYSTEM_ERASURE",
                business_impact="AVAILABILITY_IMPACT",
                evidence_chain=[ctx.source_kind, ctx.source_symbol, "SYSTEM_COMMAND", op_str],
            )
            return DestructiveEvidence(
                category=DestructiveCategory.DESTRUCTIVE_DIRECTORY_DELETE,
                root_cause=ctx.root_cause,
                impact="DESTRUCTIVE_DIRECTORY_DELETE",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                operation={"type": op_str, "target": ctx.target_resource},
                authorization={"verified": ctx.is_authorization_verified, "tenant_scoped": ctx.is_tenant_scoped},
                impact_graph={
                    "primitive": graph.primitive,
                    "capability": graph.capability,
                    "business_impact": graph.business_impact,
                },
                evidence_path=graph.evidence_chain,
                resolution="VULNERABLE",
            )

        # Step 6: Single File Erasure (unlink / remove)
        if op_str in (OperationType.REMOVE_FILE.value, "UNLINK", "DELETE_FILE"):
            return DestructiveEvidence(
                category=DestructiveCategory.DESTRUCTIVE_FILE_DELETE,
                root_cause=ctx.root_cause,
                impact="FILE_LOSS",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                operation={"type": op_str, "target": ctx.target_resource},
                authorization={"verified": ctx.is_authorization_verified, "tenant_scoped": ctx.is_tenant_scoped},
                evidence_path=[ctx.source_kind, ctx.source_symbol, "FILE_DELETE", op_str],
                resolution="VULNERABLE",
            )

        # Step 7: Cloud Object Storage Delete (DeleteObject, DeleteBucket)
        if op_str in (OperationType.DELETE_BUCKET.value, OperationType.DELETE_OBJECT.value, "STORAGE_OBJECTS_DELETE"):
            return DestructiveEvidence(
                category=DestructiveCategory.OBJECT_STORAGE_DELETE,
                root_cause=ctx.root_cause,
                impact="OBJECT_STORAGE_LOSS",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                operation={"type": op_str, "target": ctx.target_resource},
                authorization={"verified": ctx.is_authorization_verified, "tenant_scoped": ctx.is_tenant_scoped},
                evidence_path=[ctx.source_kind, ctx.source_symbol, "CLOUD_STORAGE", op_str],
                resolution="VULNERABLE",
            )

        # Step 8: Queue Systems Purge (PurgeQueue, DeleteTopic)
        if op_str in (OperationType.PURGE_QUEUE.value, "DELETE_TOPIC", "PURGE"):
            return DestructiveEvidence(
                category=DestructiveCategory.QUEUE_PURGE,
                root_cause=ctx.root_cause,
                impact="OPERATIONAL_QUEUE_DATA_LOSS",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                operation={"type": op_str, "target": ctx.target_resource},
                authorization={"verified": ctx.is_authorization_verified, "tenant_scoped": ctx.is_tenant_scoped},
                evidence_path=[ctx.source_kind, ctx.source_symbol, "MESSAGE_QUEUE", op_str],
                resolution="VULNERABLE",
            )

        # Step 9: Cache Systems Flush (FLUSHALL, FLUSHDB)
        if op_str in (OperationType.FLUSH_CACHE.value, "FLUSHALL", "FLUSHDB", "CACHE_CLEAR"):
            return DestructiveEvidence(
                category=DestructiveCategory.CACHE_FLUSH,
                root_cause=ctx.root_cause,
                impact="AVAILABILITY_DEGRADATION",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                operation={"type": op_str, "target": ctx.target_resource},
                authorization={"verified": ctx.is_authorization_verified, "tenant_scoped": ctx.is_tenant_scoped},
                evidence_path=[ctx.source_kind, ctx.source_symbol, "CACHE_SYSTEM", op_str],
                resolution="VULNERABLE",
            )

        # Step 10: Service Shutdown & Process Termination
        if op_str in (OperationType.SHUTDOWN_SERVICE.value, OperationType.KILL_PROCESS.value, "SERVICE_SHUTDOWN", "CLUSTER_DELETE"):
            graph = CapabilityImpactGraph(
                primitive=ctx.root_cause,
                capability="INFRASTRUCTURE_TERMINATION",
                business_impact="AVAILABILITY_IMPACT",
                evidence_chain=[ctx.source_kind, ctx.source_symbol, "INFRASTRUCTURE_API", op_str],
            )
            return DestructiveEvidence(
                category=DestructiveCategory.AVAILABILITY_IMPACT,
                root_cause=ctx.root_cause,
                impact="AVAILABILITY_IMPACT",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                operation={"type": op_str, "target": ctx.target_resource},
                authorization={"verified": ctx.is_authorization_verified, "tenant_scoped": ctx.is_tenant_scoped},
                impact_graph={
                    "primitive": graph.primitive,
                    "capability": graph.capability,
                    "business_impact": graph.business_impact,
                },
                evidence_path=graph.evidence_chain,
                resolution="VULNERABLE",
            )

        # Fallback General Bulk Delete
        return DestructiveEvidence(
            category=DestructiveCategory.BULK_DELETE_OPERATION,
            root_cause=ctx.root_cause,
            impact="BULK_DATA_MUTATION",
            source_kind=ctx.source_kind,
            source_symbol=ctx.source_symbol,
            operation={"type": op_str, "target": ctx.target_resource},
            authorization={"verified": ctx.is_authorization_verified, "tenant_scoped": ctx.is_tenant_scoped},
            evidence_path=[ctx.source_kind, ctx.source_symbol, "BULK_OPERATION", op_str],
            resolution="VULNERABLE",
        )
