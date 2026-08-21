"""Batch C11 Destructive Actions Golden Corpus Qualification Test Suite (200 Fixtures across 7 Languages)."""

import pytest

from karsasec.analysis.destructive.engine import DestructiveActionsReasoningEngine
from karsasec.analysis.destructive.models import (
    DestructiveContext,
    OperationType,
)

LANGUAGES = ["python", "javascript", "php", "java", "go", "ruby", "dotnet"]
OPERATIONS = [OperationType.DROP_TABLE, OperationType.TRUNCATE_TABLE, OperationType.REMOVE_DIR, OperationType.DELETE_BUCKET, OperationType.PURGE_QUEUE, OperationType.FLUSH_CACHE, OperationType.SHUTDOWN_SERVICE]

# --- 200 High-Quality Parametrized Fixtures ---

DATABASE_DESTRUCTION_POSITIVES = [
    DestructiveContext(
        source_kind="HTTP_REQUEST",
        source_symbol=f"db_op_{i}",
        operation_type=OperationType.DROP_TABLE if i % 2 == 0 else OperationType.TRUNCATE_TABLE,
        target_resource=f"table_customer_{i}",
        root_cause="SQL_INJECTION" if i % 2 == 0 else "IDOR",
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 41)
]

FILESYSTEM_DESTRUCTION_POSITIVES = [
    DestructiveContext(
        source_kind="HTTP_REQUEST",
        source_symbol=f"fs_op_{i}",
        operation_type="RM_RF" if i % 2 == 0 else OperationType.REMOVE_FILE,
        target_resource=f"/var/app/data_{i}",
        root_cause="COMMAND_INJECTION",
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 41)
]

TENANT_WIPE_POSITIVES = [
    DestructiveContext(
        source_kind="HTTP_REQUEST",
        source_symbol=f"tenant_wipe_{i}",
        operation_type=OperationType.DELETE_FROM,
        target_resource=f"TENANT_DATA_{i}",
        is_tenant_scoped=False,
        is_authorization_verified=False,
        root_cause="IDOR",
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 41)
]

INFRASTRUCTURE_DESTRUCTION_POSITIVES = [
    DestructiveContext(
        source_kind="ADMIN_API",
        source_symbol=f"infra_op_{i}",
        operation_type=OperationType.PURGE_QUEUE if i % 3 == 0 else (OperationType.FLUSH_CACHE if i % 3 == 1 else OperationType.SHUTDOWN_SERVICE),
        target_resource=f"resource_cluster_{i}",
        root_cause="SSRF",
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 41)
]

SAFE_AUTHORIZED_NEGATIVES = [
    DestructiveContext(
        source_kind="ADMIN_API",
        source_symbol=f"safe_admin_{i}",
        operation_type=OperationType.DELETE_FROM,
        target_resource=f"user_logs_{i}",
        is_authorization_verified=True,
        is_tenant_scoped=True,
        is_user_controlled=False,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 41)
]


@pytest.mark.parametrize("ctx", DATABASE_DESTRUCTION_POSITIVES)
def test_database_destruction_positives(ctx: DestructiveContext) -> None:
    engine = DestructiveActionsReasoningEngine()
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", FILESYSTEM_DESTRUCTION_POSITIVES)
def test_filesystem_destruction_positives(ctx: DestructiveContext) -> None:
    engine = DestructiveActionsReasoningEngine()
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", TENANT_WIPE_POSITIVES)
def test_tenant_wipe_positives(ctx: DestructiveContext) -> None:
    engine = DestructiveActionsReasoningEngine()
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", INFRASTRUCTURE_DESTRUCTION_POSITIVES)
def test_infrastructure_destruction_positives(ctx: DestructiveContext) -> None:
    engine = DestructiveActionsReasoningEngine()
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", SAFE_AUTHORIZED_NEGATIVES)
def test_safe_authorized_negatives(ctx: DestructiveContext) -> None:
    engine = DestructiveActionsReasoningEngine()
    ev = engine.evaluate_destructive_action(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_c11_determinism() -> None:
    """Section Determinism: Verifies repeated evaluation yields 100% identical outputs."""
    engine = DestructiveActionsReasoningEngine()
    ctx = DestructiveContext(
        source_kind="HTTP_REQUEST",
        source_symbol="tenant_id",
        operation_type=OperationType.DROP_TABLE,
        target_resource="TENANT_DATA",
        root_cause="IDOR",
    )

    ev1 = engine.evaluate_destructive_action(ctx)
    ev2 = engine.evaluate_destructive_action(ctx)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()
