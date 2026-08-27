# Sprint F11 — Security Invariants: AI Gateway Resilience & Provider Execution Security

**Date**: 2026-08-20  
**Target Architecture**: KarsaSec External AI Provider Execution Boundary  
**Status**: Formal Specification  

---

## Formal Invariants List

### INV-F11-TIMEOUT-01: Hard Per-Attempt Timeout Isolation
- **Statement**: A provider execution attempt must never block the executing worker thread/loop beyond the configured `per_attempt_timeout_seconds`.
- **Enforcement**: Wrapped in hard timeout boundary (`asyncio.wait_for` or socket timeout). On timeout, connection is forcefully aborted, attempt is marked with `ATTEMPT_ERROR_TIMEOUT`, and reserved budget is handled safely without worker hang.
- **Fail-Closed**: Exceeding timeout immediately triggers attempt cancellation.

### INV-F11-RETRY-02: Retries Must Not Bypass Core Security Controls
- **Statement**: Any retried provider attempt must independently respect budget reservations, monotonic lease versioning, idempotency checks, and tenant authorization.
- **Enforcement**: Retries must execute within active request reservation bounds; token budget must never be double-charged or leaked across retries.

### INV-F11-RETRY-03: Hard Bounded Retry Count
- **Statement**: Total execution attempts for any single AI request must be strictly bounded ($1 \le \text{attempts} \le N_{max}$, default $N_{max} = 3$).
- **Enforcement**: Database unique constraint `UNIQUE(request_id, attempt_number)` enforced in `AIProviderAttemptModel`. Request state machine transitions to `FAILED` or `PERMANENT_FAILURE` when attempt count reaches $N_{max}$.

### INV-F11-BACKOFF-04: Bounded and Deterministic Backoff
- **Statement**: Retry delays must use exponential backoff with full jitter, strictly capped at `max_backoff_seconds` (default 30s). Under test conditions (mocked time/seed), backoff sequence must be 100% deterministic.
- **Enforcement**: $\text{delay} = \min(T_{max}, T_{base} \times 2^{\text{attempt}-1} \times \text{jitter\_factor})$.

### INV-F11-CIRCUIT-05: Circuit Breaker Isolation & Traffic Rejection
- **Statement**: An unhealthy provider whose circuit state is `OPEN` must be immediately bypassed by the provider router without invoking network connections or consuming execution worker slots.
- **Enforcement**: `ProviderRouter._filter_eligible` queries circuit state; `OPEN` circuit state causes immediate fail-closed candidate rejection.

### INV-F11-RATE-06: Atomic Distributed Rate Limiting
- **Statement**: Distributed rate limit counters must be updated and checked atomically to prevent race-condition quota bypasses across concurrent workers.
- **Enforcement**: Atomic token bucket or sliding window algorithm with non-negative counter invariants.

### INV-F11-CONCURRENCY-07: Provider Concurrency Bound
- **Statement**: The number of concurrent in-flight requests to any single provider/model target must never exceed `max_concurrent_requests`.
- **Enforcement**: Bounded semaphore or atomic slot reservation. Excess requests are rejected with `ATTEMPT_ERROR_RATE_LIMIT` or routed to fallback providers.

### INV-F11-SSRF-08: Forbidden Endpoint Destination Rejection
- **Statement**: Provider requests must never reach loopback (`127.0.0.1`, `::1`), private IP ranges (RFC 1918), link-local (`169.254.169.254`), multicast, or non-HTTPS destinations unless explicitly configured for local testing.
- **Enforcement**: `EndpointSecurityPolicy` pre-flight URL parsing, DNS resolution validation, and socket address filtering.

### INV-F11-REDIRECT-09: Per-Hop Redirect Policy Validation
- **Statement**: HTTP redirects must never bypass endpoint security policy.
- **Enforcement**: Automatic HTTP redirect following is disabled or capped at max 3 hops. Every redirect target URL is fully re-validated against `EndpointSecurityPolicy`.

### INV-F11-RESPONSE-10: Bounded & Validated Provider Response
- **Statement**: Provider response payloads must be strictly bounded in size ($\le 10\text{MB}$) and validated before being written to persistent storage or passed to downstream parsers.
- **Enforcement**: Response stream byte counter aborts reading if size exceeds maximum permitted threshold.

### INV-F11-CANCEL-11: Cancellation Atomicity & Budget Safety
- **Statement**: Cancelling an in-flight request must immediately abort active provider connections, release reserved token budget, and transition request state cleanly without double-releases or orphan reservations.
- **Enforcement**: `AIRequestStateService.release_reservation` executes atomic CAS status transition to `STATE_CANCELLED`.

### INV-F11-FENCE-12: Stale Execution Write Fencing
- **Statement**: A worker attempt executing with an expired lease or stale fencing token must be rejected from writing authoritative response data or committing budget.
- **Enforcement**: Monotonic `lease_version` fencing verification on state transitions.

### INV-F11-SECRET-13: Absolute Secret Isolation in Telemetry & Storage
- **Statement**: Provider API keys, bearer tokens, or raw authorization headers must never be written to logs, events, traces, exception error messages, or persistent tables.
- **Enforcement**: Strict error taxonomy (`KNOWN_ERROR_CLASSES`) in `AIProviderAttemptModel.error_class` and header sanitization.

### INV-F11-METRICS-14: Unbounded Metrics Cardinality Prevention
- **Statement**: Dynamic or untrusted inputs must never be used as Prometheus/OpenTelemetry metric tag values.
- **Enforcement**: Metric label values are validated against an explicit allowlist of registered provider IDs, model IDs, and status codes.

### INV-F11-FAILURE-15: Deterministic Failure Classification
- **Statement**: HTTP status codes and network errors must be deterministically classified into `RETRYABLE` (502, 503, 504, connection drop, timeout) vs `NON_RETRYABLE` (400, 401, 403, 404, 422). Client errors (4xx) must never trigger retries or circuit breaker trips.
- **Enforcement**: `FailureClassifier` engine evaluating status code and exception type.
