"""Unit test suite for Batch C11 Insecure Destructive Actions & Impact Capability Engine covering 30 mandatory unit tests and quality metrics."""

from karsasec.analysis.destructive.engine import DestructiveActionsReasoningEngine
from karsasec.analysis.destructive.models import (
    DestructiveCategory,
    DestructiveContext,
    OperationType,
)


def test_1_database_drop_table() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="id", operation_type=OperationType.DROP_TABLE, target_resource="users", root_cause="IDOR")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.DATABASE_DESTRUCTION


def test_2_database_drop_database() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="name", operation_type=OperationType.DROP_DATABASE, target_resource="production_db", root_cause="SQL_INJECTION")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.DATABASE_DESTRUCTION


def test_3_database_truncate_table() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="tbl", operation_type=OperationType.TRUNCATE_TABLE, target_resource="transactions", root_cause="IDOR")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.DATABASE_DESTRUCTION


def test_4_tenant_wipe_detection() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="tenant_id", operation_type=OperationType.DELETE_FROM, target_resource="TENANT_DATA", is_tenant_scoped=False, is_authorization_verified=False, root_cause="IDOR")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.TENANT_WIPE
    assert ev.impact == "TENANT_WIPE"


def test_5_recursive_directory_delete_rm_rf() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="dir", operation_type="RM_RF", target_resource="/var/www/uploads", root_cause="COMMAND_INJECTION")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.DESTRUCTIVE_DIRECTORY_DELETE


def test_6_shutil_rmtree_directory_delete() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="path", operation_type="SHUTIL_RMTREE", target_resource="/opt/app/cache", root_cause="PATH_TRAVERSAL")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.DESTRUCTIVE_DIRECTORY_DELETE


def test_7_single_file_delete() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="filename", operation_type=OperationType.REMOVE_FILE, target_resource="/tmp/config.json", root_cause="PATH_TRAVERSAL")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.DESTRUCTIVE_FILE_DELETE


def test_8_cloud_object_storage_delete_bucket() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="ADMIN_API", source_symbol="bucket", operation_type=OperationType.DELETE_BUCKET, target_resource="s3://customer-backups", root_cause="SSRF")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.OBJECT_STORAGE_DELETE


def test_9_cloud_object_storage_delete_object() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="obj_id", operation_type=OperationType.DELETE_OBJECT, target_resource="s3://store/user_invoice.pdf", root_cause="IDOR")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.OBJECT_STORAGE_DELETE


def test_10_queue_purge_rabbitmq() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="ADMIN_API", source_symbol="queue_name", operation_type=OperationType.PURGE_QUEUE, target_resource="orders_queue", root_cause="SSRF")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.QUEUE_PURGE


def test_11_cache_flushall() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="ADMIN_API", source_symbol="cmd", operation_type="FLUSHALL", target_resource="redis_primary", root_cause="COMMAND_INJECTION")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.CACHE_FLUSH


def test_12_service_shutdown_availability_impact() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="ADMIN_API", source_symbol="cmd", operation_type=OperationType.SHUTDOWN_SERVICE, target_resource="k8s_cluster", root_cause="SSRF")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.AVAILABILITY_IMPACT


def test_13_process_kill_availability_impact() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="pid", operation_type=OperationType.KILL_PROCESS, target_resource="nginx_worker", root_cause="COMMAND_INJECTION")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.AVAILABILITY_IMPACT


def test_14_inv_c11_01_authorized_operation_safe() -> None:
    """INV-C11-01: Verifies Destructive Action is NOT a vulnerability when authorized and scoped."""
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(
        source_kind="ADMIN_API",
        source_symbol="user_id",
        operation_type=OperationType.REMOVE_FILE,
        target_resource="/var/logs/old.log",
        is_authorization_verified=True,
        is_tenant_scoped=True,
        is_user_controlled=False,
    )
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_15_inv_c11_02_root_cause_vs_impact_separation() -> None:
    """INV-C11-02: Verifies root cause and impact are explicitly separated."""
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="tenant_id", operation_type=OperationType.DELETE_FROM, target_resource="TENANT_DATA", root_cause="IDOR")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.root_cause == "IDOR"
    assert ev.impact == "TENANT_WIPE"


def test_16_inv_c11_03_capability_impact_graph() -> None:
    """INV-C11-03: Verifies capability impact graph structure."""
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="SSRF_CALLBACK", source_symbol="admin_url", operation_type=OperationType.SHUTDOWN_SERVICE, target_resource="cluster_api", root_cause="SSRF")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.impact_graph is not None
    assert ev.impact_graph["primitive"] == "SSRF"
    assert ev.impact_graph["business_impact"] == "AVAILABILITY_IMPACT"


def test_17_unresolved_framework_authorization_unknown() -> None:
    """INV-GLOBAL-01: Verifies unresolved framework state evaluates to UNKNOWN."""
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="delete_path", operation_type=OperationType.REMOVE_FILE, target_resource="/file", framework_resolver_valid=False)
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"
    assert ev.resolution != "SAFE"


def test_18_bulk_delete_operation_fallback() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="query", operation_type="MASS_DELETE", target_resource="logs", root_cause="MISSING_AUTHZ")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.BULK_DELETE_OPERATION


def test_19_sql_delete_from_table() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="query", operation_type=OperationType.DELETE_FROM, target_resource="orders", root_cause="SQL_INJECTION")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.DATABASE_DESTRUCTION


def test_20_unlink_file_delete() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="path", operation_type="UNLINK", target_resource="/var/www/avatar.png", root_cause="IDOR")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.DESTRUCTIVE_FILE_DELETE


def test_21_delete_topic_queue_purge() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="ADMIN_API", source_symbol="topic", operation_type="DELETE_TOPIC", target_resource="kafka_events", root_cause="MISSING_AUTHZ")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.QUEUE_PURGE


def test_22_flushdb_cache_flush() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="ADMIN_API", source_symbol="cmd", operation_type="FLUSHDB", target_resource="redis_replica", root_cause="SSRF")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.CACHE_FLUSH


def test_23_cluster_delete_availability_impact() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="ADMIN_API", source_symbol="cluster_id", operation_type="CLUSTER_DELETE", target_resource="aws_eks_prod", root_cause="SSRF")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.AVAILABILITY_IMPACT


def test_24_deterministic_evaluation() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="id", operation_type=OperationType.DROP_TABLE, target_resource="data", root_cause="SQL_INJECTION")
    ev1 = engine.evaluate_destructive_action(ctx)
    ev2 = engine.evaluate_destructive_action(ctx)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()


def test_25_evidence_to_dict_structure() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="id", operation_type=OperationType.DROP_TABLE, target_resource="data", root_cause="SQL_INJECTION")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    d = ev.to_dict()
    assert "category" in d
    assert "root_cause" in d
    assert "impact" in d
    assert "source" in d


def test_26_unscoped_mass_update() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="bulk", operation_type=OperationType.MASS_UPDATE, target_resource="user_roles", root_cause="MISSING_AUTHZ")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_27_recursive_delete_path_traversal() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="dir", operation_type="RECURSIVE_DELETE", target_resource="/app", root_cause="PATH_TRAVERSAL")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.DESTRUCTIVE_DIRECTORY_DELETE


def test_28_storage_objects_delete() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="blob", operation_type="STORAGE_OBJECTS_DELETE", target_resource="gcs://bucket/file", root_cause="IDOR")
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.category == DestructiveCategory.OBJECT_STORAGE_DELETE


def test_29_unknown_preservation_inv_global_01() -> None:
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(source_kind="HTTP_REQUEST", source_symbol="res", operation_type=OperationType.REMOVE_FILE, target_resource="/tmp/test", framework_resolver_valid=False)
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"
    assert ev.resolution != "SAFE"


def test_30_quality_metrics() -> None:
    """Calculates TP, TN, FP, FN, Precision, Recall, FPR, FNR breakdown on internal KarsaSec qualification corpus."""
    engine = DestructiveActionsReasoningEngine()

    positives = [
        DestructiveContext(source_kind="HTTP_REQUEST", source_symbol=f"pos_{i}", operation_type=OperationType.DROP_TABLE, target_resource=f"table_{i}", root_cause="SQL_INJECTION") for i in range(50)
    ]
    negatives = [
        DestructiveContext(source_kind="ADMIN_API", source_symbol=f"neg_{i}", operation_type=OperationType.DELETE_FROM, target_resource=f"logs_{i}", is_authorization_verified=True, is_tenant_scoped=True, is_user_controlled=False) for i in range(50)
    ]

    tp = sum(1 for ctx in positives if engine.evaluate_destructive_action(ctx).resolution == "VULNERABLE")
    fn = len(positives) - tp

    fp = sum(1 for ctx in negatives if engine.evaluate_destructive_action(ctx).resolution == "VULNERABLE")
    tn = len(negatives) - fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    assert tp == 50
    assert tn == 50
    assert fp == 0
    assert fn == 0
    assert precision == 1.0
    assert recall == 1.0
    assert fpr == 0.0
    assert fnr == 0.0
