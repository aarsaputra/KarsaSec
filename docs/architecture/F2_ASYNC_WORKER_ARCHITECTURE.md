# F2 Async Worker & Distributed Execution Architecture

This document specifies the asynchronous background task processing and worker pool architecture for KarsaSec.

## 1. Overview
Sprint F2 shifts KarsaSec's REST API execution model from synchronous request-response execution to an asynchronous, worker-driven queue model. This ensures that large repositories, long-running scans, and complex remediation processes do not cause HTTP request timeouts or block API performance.

```text
                  FastAPI Client
                        │
             POST /api/v1/remediations
                        │
                        ▼
                Remediation Router
                        │
                        ▼
               RemediationService
                        │ (validate DTO & idempotency fingerprint)
                        ├──────────────────────────┐
                        ▼                          ▼
                 TaskRepository             TaskQueue (Redis)
            (InMemory/Persistence)                 │
                        │                          ▼
                        │                      Worker Pool
                        │                 (WorkerRuntimeAdapter)
                        │                          │
                        │                          ▼
                        │                  LifecycleEngine (E13)
                        │                          │
                        │                          ▼
                        │                   RTPBuilder (F0)
                        │                          │
                        │                          ▼
                        │                  RTPValidator (F0)
                        │                          │
                        │                          ▼
                        │                 VerificationReceipt
                        │                          │
                        └──────────────────────────┼──────────────────────────┐
                                                   ▼                          ▼
                                          TaskRepository Update      TaskQueue Acknowledge
```

---

## 2. Invariants Preservation (L7 Zero-LLM & Non-Authority Invariant)
* **API Non-Authority**: The HTTP/REST API endpoints (`/remediations` and `/tasks`) are completely non-authoritative. They only submit task metadata or query task status.
* **Worker Non-Authority**: The background Worker pool executing tasks does not dictate security verdicts. The `security_verification_status` of a remediation is computed *strictly* by passing the E13 scan outcomes through the `RTPValidator.validate(rtp)` function at the end of execution.
* **Output-Only Status**: The `security_verification_status` remains an output-only DTO field, never read from client input, and never hardcoded in any router or task submission service.

---

## 3. Core Architectural Components

### 3.1 Queue Layer (`karsasec/workers/queue.py`)
Provides an abstract base class `TaskQueue` for enqueueing, dequeueing, and acknowledging task execution payloads.
* `enqueue(task_id: str) -> None`
* `dequeue(timeout: int = 1) -> str | None`
* `acknowledge(task_id: str) -> None`
* `requeue(task_id: str) -> None`

### 3.2 Redis Implementation (`karsasec/workers/redis_queue.py`)
Implements `RedisTaskQueue` using Redis list primitives. It uses `BRPOPLPUSH` (or `LMOVE` with block) to ensure **reliable queue execution** (i.e., a task is moved to a "processing" list when dequeued, and only removed when acknowledged, preventing task loss on worker crash).

### 3.3 Task Repository (`karsasec/workers/repository.py`)
Decouples the queue from the State of Truth. Redis is strictly a queue transport. Task data is stored in a `TaskRepository` interface:
* `create_task(task: RemediationTask) -> None`
* `get_task(task_id: str) -> RemediationTask | None`
* `update_task(task_id: str, **kwargs) -> RemediationTask`
* `get_active_task_by_fingerprint(fingerprint: str) -> RemediationTask | None`

For Sprint F2, an `InMemoryTaskRepository` is used, paving the way for `PostgreSQLTaskRepository` in F3.

### 3.4 Task State Machine (`karsasec/workers/task.py`)
Tracks background operations across 6 states:
* `PENDING`: Task registered but not yet submitted.
* `QUEUED`: Task submitted to the task queue.
* `RUNNING`: Task picked up by a worker.
* `COMPLETED`: Task successfully processed, producing a `VerificationReceipt`.
* `FAILED`: Task execution encountered an unhandled exception, exceeding max retries.
* `CANCELLED`: Task execution explicitly stopped by system request.

### 3.5 Lease Timeout & Worker Crash Recovery
To avoid tasks lingering in `RUNNING` state indefinitely if a worker crashes:
* Each task possesses a `lease_seconds` (default: 300).
* A background manager or loop calls `recover_stale_tasks()` which scans the processing list for expired leases and requeues them.

### 3.6 Worker Runtime Adapter (`karsasec/workers/worker.py` & `celery_app.py`)
To isolate Celery as an adapter rather than hardcoding it into the core, we introduce `WorkerRuntime(ABC)` with implementations:
* `CustomWorkerRuntime` (custom polling queue loop)
* `CeleryWorkerRuntime` (adapter routing to Celery task workers)

---

## 4. Idempotency & Replay Prevention
Task submissions calculate a deterministic `fingerprint` using SHA-256 over a canonical representation of the remediation request payload (analogous to the F0 RTP fingerprint).
* If a task with the same fingerprint is in `QUEUED` or `RUNNING` or `COMPLETED` state, the router returns the existing `task_id` instead of launching duplicate queue tasks.
* Submitting the same idempotency key concurrently is safely deduplicated.
