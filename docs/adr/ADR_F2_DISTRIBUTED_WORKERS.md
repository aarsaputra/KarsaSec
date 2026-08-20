# ADR_F2_DISTRIBUTED_WORKERS: Async Worker & Background Queue Architecture

## Status
PROPOSED

## Context
Sprint F1 established a synchronous, in-memory REST API layer. While this is sufficient for basic testing, a production-ready enterprise security platform must support long-running security scans and multi-stage remediation tasks asynchronously to avoid API gateway timeouts (e.g. 30-second standard proxy limits) and resource exhaustion under load.

## Decision
We will implement an asynchronous worker runtime utilizing a Redis-backed queue layer, worker pool architecture, and state persistence abstraction.

1. **Abstract Queue Interface (`TaskQueue`)**: We define an abstract `TaskQueue` with `enqueue()`, `dequeue()`, `acknowledge()`, and `requeue()` operations to support custom and framework-based backends.
2. **Redis Reliable Queue Implementation (`RedisTaskQueue`)**: We implement the queue using Redis client lists with a reliable queue pattern (using `rpush` to submit and `brpoplpush` to consume tasks into a processing queue, then `lrem` to acknowledge).
3. **Decoupled Task Repository (`TaskRepository`)**: To prevent Redis from acting as the source of truth for task state, we define a `TaskRepository` interface with `InMemoryTaskRepository` as the default implementation for F2 (to be replaced by DB storage in F3).
4. **Worker Runtime Portability (`WorkerRuntime`)**: Worker execution is decoupled via a `WorkerRuntime` interface to allow switching between custom queue poll loops and standard Celery adapters.
5. **Worker Lease Timeout & Crash Recovery**: Tasks in `RUNNING` state have a lease timeout (e.g. 300 seconds). A periodic recovery loop scans active/processing leases, automatically requeueing stale tasks.
6. **Task Retry Policy**: Transient errors (e.g. database locks, network timeout) trigger up to 3 retries, transitioning tasks from `RUNNING` -> `FAILED_RETRYABLE` -> `QUEUED`. If attempts >= 3, tasks are marked `FAILED`.
7. **Idempotency Fingerprinting**: Request validation computes a SHA-256 hash over canonical JSON representations of the request payload to map to active or completed task IDs, preventing duplicate job submissions.

## Invariants & Compliance
* **L7 Invariant**: The worker is NOT a security authority. It must validate the E13 execution outcome through the `RTPValidator` to set `security_verification_status` and generate the receipt.
* **Privacy Boundaries (R7-R9)**: Task states and logs must NEVER contain source code, diffs, or credentials.
* **Execution Safety (Capability Audit)**: Worker tasks must run purely within the Python AST and KarsaSec core, and must not execute raw shell commands or dangerous eval/exec routines.
