# F3 Persistence Architecture & Enterprise State Management

## 1. Overview

Sprint F3 transitions KarsaSec from volatile, in-memory repositories (`InMemoryTaskRepository`) to a production-grade PostgreSQL persistence engine built with SQLAlchemy 2.x and Alembic migrations.

## 2. Architecture & Design Principles

```
                              +-------------------------+
                              |   REST API / Service    |
                              +------------+------------+
                                           |
                                           v
                              +-------------------------+
                              |  PostgresTaskRepository |
                              +------------+------------+
                                           |
                    +----------------------+----------------------+
                    |                      |                      |
                    v                      v                      v
           +-----------------+    +------------------+   +-------------------+
           |    tasks        |    |    receipts      |   |   audit_events    |
           | (State Machine) |    |  (Immutable)     |   |   (Append-Only)   |
           +-----------------+    +------------------+   +-------------------+
```

### Key Components

1. **`PostgresTaskRepository`**: Implements `TaskRepository` interface using SQLAlchemy 2.x. Manages task lifecycle transitions (`PENDING` -> `QUEUED` -> `RUNNING` -> `COMPLETED`/`FAILED`).
2. **`PostgresReceiptRepository`**: Implements `ReceiptRepository` interface. Stores `VerificationReceipt` records with a strict write-once constraint (immutable).
3. **`PostgresAuditRepository`**: Implements `AuditRepository`. Provides an append-only ledger for all task lifecycle events (`TASK_CREATED`, `TASK_QUEUED`, `TASK_STARTED`, `TASK_RETRIED`, `TASK_COMPLETED`, `TASK_FAILED`, `TASK_CANCELLED`, `TASK_RECOVERED`).
4. **`StartupRecoveryEngine`**: Evaluates `RUNNING` tasks whose persistent wall-clock lease has expired upon application boot, automatically transitioning them to `QUEUED` and re-enqueueing.

## 3. Invariants & Security Boundaries

* **L7 Zero Security Authority**: `security_verification_status` is an output-only database attribute. Neither API endpoints nor database repositories generate or force security statuses; statuses originate exclusively from `RTPValidator.validate()`.
* **Privacy Boundary (R7-R9)**: Database schemas omit source code, unified diffs, patches, credentials, API keys, or raw tokens. Only fingerprints, task metadata, and status strings are stored.
* **Deterministic Queries**: All list queries enforce explicit `ORDER BY` sorting (e.g., `created_at ASC, task_id ASC`) to eliminate non-deterministic ordering.
* **Audit Immutability**: `audit_events` allows `INSERT` operations only; `UPDATE` and `DELETE` queries are strictly prohibited.
