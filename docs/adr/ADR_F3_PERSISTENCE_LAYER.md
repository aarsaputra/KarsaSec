# ADR F3: Persistent Storage, Audit Trail & Enterprise State Management

## Status
Accepted (Sprint F3 = ARCHITECTURALLY VERIFIED)

## Context
Prior to Sprint F3, KarsaSec relied on an in-memory repository (`InMemoryTaskRepository`) for managing remediation tasks, receipts, and execution states. Server restarts caused task loss, receipt loss, and complete wipe of remediation histories.

## Decision
We implement a production-grade PostgreSQL persistence layer using SQLAlchemy 2.x and Alembic migrations under `karsasec/persistence/`.

### Core Architectural Choices
1. **Schema Separation**:
   - `tasks`: State machine and lease tracking table.
   - `receipts`: Write-once immutable table for `VerificationReceipt` records.
   - `audit_events`: Append-only audit trail table for tracking task events.

2. **Zero Security Authority (L7)**:
   Database models do not calculate or default security verdicts. `security_verification_status` is populated exclusively from `RTPValidator.validate()` outputs.

3. **Privacy Safeguards (R7-R9)**:
   The database schema excludes source code, diffs, patches, credentials, tokens, or API keys. Privacy sanitization guards run prior to persisting audit event details.

4. **Startup Task Recovery Engine**:
   A dedicated `StartupRecoveryEngine` runs on application initialization. It scans for tasks stranded in `RUNNING` state with expired leases (>300s) and requeues them automatically.

5. **Determinism**:
   All database queries specify explicit `ORDER BY` clauses to ensure deterministic behavior across sequential calls and test runs.

## Consequences
- Server restarts retain state, receipts, and audit histories in PostgreSQL.
- Stalled tasks after crashes automatically recover via `StartupRecoveryEngine`.
- Enterprise state management complies with all L7 and privacy invariants.
