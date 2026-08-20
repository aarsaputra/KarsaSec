# Phase 1 — Repository Dependency Analysis

## Overview
This document presents the structural, dependency, ORM, and migration graph analysis for the `karsasec/persistence/` module introduced in Sprint F3.

---

## 1. Module File Map
```text
karsasec/persistence/
├── __init__.py                (Module metadata & invariants)
├── db.py                      (DatabaseEngine singleton & session factory)
├── models.py                  (SQLAlchemy 2.x Declarative Base & ORM Models)
├── task_repository.py         (PostgresTaskRepository implementation)
├── receipt_repository.py      (PostgresReceiptRepository implementation)
├── audit_repository.py        (PostgresAuditRepository implementation)
├── recovery.py                 (StartupRecoveryEngine implementation)
└── migrations/
    ├── env.py                 (Alembic environment configuration)
    ├── script.py.mako         (Alembic migration template)
    └── versions/
        └── 16e35b77308a_initial_schema.py  (Initial PostgreSQL DDL Migration)
```

---

## 2. Dependency Graph

```mermaid
graph TD
    subgraph Core Framework & Workers
        RemediationTask[karsasec.workers.task.RemediationTask]
        TaskRepositoryContract[karsasec.workers.repository.TaskRepository]
        TaskQueueContract[karsasec.workers.queue.TaskQueue]
    end

    subgraph Persistence Layer
        DB[karsasec.persistence.db]
        Models[karsasec.persistence.models]
        PostgresTaskRepo[karsasec.persistence.task_repository.PostgresTaskRepository]
        PostgresReceiptRepo[karsasec.persistence.receipt_repository.PostgresReceiptRepository]
        PostgresAuditRepo[karsasec.persistence.audit_repository.PostgresAuditRepository]
        RecoveryEngine[karsasec.persistence.recovery.StartupRecoveryEngine]
    end

    subgraph Migration Infrastructure
        AlembicEnv[karsasec.persistence.migrations.env]
        InitialSchema[migrations.versions.16e35b77308a_initial_schema]
    end

    DB -->|imports| Models
    PostgresTaskRepo -->|uses| DB
    PostgresTaskRepo -->|uses| Models
    PostgresTaskRepo -->|implements| TaskRepositoryContract
    PostgresTaskRepo -->|maps| RemediationTask

    PostgresReceiptRepo -->|uses| DB
    PostgresReceiptRepo -->|uses| Models

    PostgresAuditRepo -->|uses| DB
    PostgresAuditRepo -->|uses| Models

    RecoveryEngine -->|uses| PostgresTaskRepo
    RecoveryEngine -->|uses| TaskQueueContract
    RecoveryEngine -->|uses| PostgresAuditRepo

    AlembicEnv -->|imports| Models
    InitialSchema -->|reflects| Models
```

---

## 3. ORM Graph & Schema Constraints

```mermaid
erDiagram
    TASKS {
        uuid id PK
        string task_id UK "unique index"
        string finding_id
        string approval_token_id
        string fingerprint "indexed"
        string state
        integer attempts
        integer max_attempts
        integer lease_seconds
        timestamp lease_started_at "indexed"
        text error_message
        string receipt_id
        string receipt_fingerprint
        string security_verification_status "output-only"
        timestamp created_at
        timestamp updated_at
    }

    RECEIPTS {
        uuid id PK
        string receipt_id UK "unique index"
        string transaction_id "indexed"
        string finding_id
        string rule_id
        string receipt_version
        string integrity_status
        string security_verification_status
        string verification_run_id
        integer matching_findings_count
        string proposal_fingerprint
        string provenance_fingerprint
        string ledger_fingerprint
        string receipt_fingerprint UK "unique constraint"
        timestamp created_at
    }

    AUDIT_EVENTS {
        uuid id PK
        string task_id FK "tasks.task_id (CASCADE)"
        string event_type
        text details "JSON sanitized"
        timestamp created_at "composite index (task_id, created_at)"
    }

    TASKS ||--o{ AUDIT_EVENTS : "1 to N append-only"
```

---

## 4. Architectural Summary & Verification
1. **Isolation**: `models.py` does not import any AI engines, worker runtimes, routers, or static analysis tools.
2. **Coupling**: The persistence layer strictly implements abstract repository contracts from `karsasec.workers.repository`.
3. **Database Drivers**: Utilizes SQLAlchemy 2.x standard dialect configuration with PostgreSQL-native `UUID` types.
