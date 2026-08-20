# ADR-F1: Enterprise REST API Architecture & Service Boundary

* **Status**: Proposed
* **Deciders**: KarsaSec Engineering Team
* **Date**: 2026-08-13

---

## Context and Problem Statement

Following the completion of Sprint E13 (Remediation Lifecycle Engine & Provenance DAG) and Sprint F0 (Remediation Transaction Package & Verification Receipt), KarsaSec requires an enterprise-ready HTTP REST API layer (Sprint F1). 

The REST API must allow enterprise clients, CI/CD pipelines, and web dashboards to trigger security scans, query findings, request automated remediations, and retrieve cryptographic verification receipts.

However, web API layers often introduce security risks such as bypass of business state machines, leakage of sensitive code/secrets, arbitrary client-side state manipulation, or reliance on heuristic AI outputs. How do we architect the FastAPI REST API layer so that it acts purely as a thin, secure adapter without becoming a security authority or bypassing established E13/F0 invariants?

---

## Decision Drivers

1. **API != Security Authority**: The API layer MUST NOT evaluate security claims, force state transitions, or decide whether a vulnerability is fixed. Security truth originates strictly from E13/F0 SAST rescan engines.
2. **DTO & Privacy Boundaries**: Domain objects MUST NOT be serialized directly to HTTP responses. Data Transfer Objects (DTOs) must filter out sensitive source code, unified diff hunks, secrets, and internal prompts.
3. **Deterministic Response Contracts**: All collection responses must maintain stable sorting to guarantee response determinism across `PYTHONHASHSEED` variations.
4. **Idempotency & Correlation**: Every API request must carry or generate an `X-Request-ID` correlation header, and mutating endpoints (e.g. `/api/v1/remediations`) must support `Idempotency-Key` headers.
5. **No External Worker Queues in F1**: F1 focuses exclusively on synchronous REST API endpoints and service interfaces. Asynchronous queues (Celery/Redis) belong strictly to Sprint F2.

---

## Decision Outcome

We decided to implement the **Enterprise REST API Layer (`karsasec.server`)** in Sprint F1 using FastAPI and Pydantic v2.

### Architecture Key Principles

1. **Router & Service Separation**:
   - `karsasec.server.api.v1`: HTTP route handlers responsible solely for request validation, authorization checks, and DTO transformation.
   - `karsasec.server.services`: Application service layer encapsulating domain calls to `execute_scan_command`, `RemediationLifecycleEngine`, and `RTPValidator`.
2. **Security & Authentication Boundary**:
   - `AuthenticationProvider` interface resolving `Principal` identities.
   - Decoupled `authorize(principal, action, resource)` permission boundary protecting `/api/v1/*` routes.
3. **Zero Security Authority Enforcement**:
   - Remediation trigger `/api/v1/remediations` invokes `RemediationLifecycleEngine.execute()`, which generates an `RTP` and `VerificationReceipt`.
   - The API response reflects `security_verification_status` derived strictly from the `RTPValidator` evaluation of the SAST rescan.
4. **OpenAPI 3.1 & Error Schema**:
   - Custom exception handler returning structured `APIErrorResponse` with standard HTTP status codes (`400`, `401`, `403`, `404`, `409`, `422`, `500`) without exposing internal tracebacks.

---

## Consequences

### Positive
- Enterprise clients gain a clean, OpenAPI 3.1-compliant interface under `/api/v1/`.
- All E13 state machine and F0 privacy/cryptographic invariants are preserved with 0 risk of API-level bypass.
- Clear separation of concerns enables Sprint F2 (Workers) and Sprint F4 (Multi-Tenant RBAC) to reuse the `services` and `security` abstractions cleanly.

### Negative
- Synchronous scan execution on large repositories via `/api/v1/scans` may take several seconds; long-running background tasks will be handled when Sprint F2 introduces worker queues.
