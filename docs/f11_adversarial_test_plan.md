# Sprint F11 — Adversarial Test Plan: Resilience & Provider Security

**Date**: 2026-08-20  
**Target Suite**: `tests/ai/test_f11_phase5_*.py`  
**Status**: Test Strategy & Adversarial Specification  

---

## Adversarial Test Suites Overview

The F11 adversarial suite validates external execution security, timeout isolation, circuit breaker correctness, rate limiting, and SSRF prevention under hostile attack conditions.

---

## Test Categories & Invariants Matrix

| Category ID | Adversarial Test Name | Target Invariant | Attacker Setup / Injection | Expected Security Result |
| :---: | :--- | :--- | :--- | :--- |
| **ADV-01** | `test_hard_timeout_aborts_hanging_worker` | `INV-F11-TIMEOUT-01` | Mock provider connection hangs for 60s; per-attempt timeout set to 2s. | Connection aborted at 2s; `ATTEMPT_ERROR_TIMEOUT` recorded; worker unblocked immediately. |
| **ADV-02** | `test_retry_storm_exponential_backoff_and_cap` | `INV-F11-BACKOFF-04` | 50 concurrent requests trigger 503 Service Unavailable retries. | Retries execute with exponential backoff + jitter capped at 30s; total request rate remains within limit. |
| **ADV-03** | `test_retry_amplification_bounded_at_max_attempts` | `INV-F11-RETRY-03` | Provider fails 10 consecutive attempts; request max attempts = 3. | Request attempts strictly capped at 3; status transitions to `FAILED`; budget released cleanly. |
| **ADV-04** | `test_concurrent_retry_idempotency_locking` | `INV-F11-RETRY-02` | 10 workers race to retry the same failed attempt simultaneously. | Only 1 worker wins CAS lock; remaining 9 workers receive `AIRequestStateConflictError`. |
| **ADV-05** | `test_circuit_breaker_trips_open_on_5xx_threshold` | `INV-F11-CIRCUIT-05` | Inject 5 consecutive HTTP 500 errors into provider endpoint. | Circuit state transitions to `OPEN`; router immediately bypasses provider without network call. |
| **ADV-06** | `test_rate_limiter_atomic_token_bucket_race` | `INV-F11-RATE-06` | 100 concurrent workers query rate limit of 10 requests/sec. | Exactly 10 requests proceed; 90 requests rejected with `ATTEMPT_ERROR_RATE_LIMIT`. Zero counter drift. |
| **ADV-07** | `test_provider_concurrency_semaphore_bound` | `INV-F11-CONCURRENCY-07` | 20 concurrent requests issued to provider with max concurrency = 5. | Exactly 5 requests execute concurrently; 15 requests queued/routed to fallback. |
| **ADV-08** | `test_stale_worker_lease_fencing_rejection` | `INV-F11-FENCE-12` | Worker execution delayed beyond lease expiration; attempts to commit result. | Commit rejected due to fencing version mismatch; zero database state mutation. |
| **ADV-09** | `test_in_flight_cancellation_releases_budget_cleanly` | `INV-F11-CANCEL-11` | Send cancellation signal while provider execution is `IN_FLIGHT`. | HTTP connection aborted; reserved tokens returned to budget; state transitions to `CANCELLED`. |
| **ADV-10** | `test_duplicate_attempt_creation_rejection` | `INV-F11-RETRY-03` | Inject duplicate `attempt_number` creation for single `request_id`. | Database `UNIQUE` constraint raises `InvalidAttemptError`; duplicate record rejected. |
| **ADV-11** | `test_ssrf_rejects_localhost_ip` | `INV-F11-SSRF-08` | Set provider URL to `https://127.0.0.1:8443/v1/chat`. | `EndpointSecurityPolicy` raises `SSRFSecurityError`; zero network packets sent. |
| **ADV-12** | `test_ssrf_rejects_private_rfc1918_ip` | `INV-F11-SSRF-08` | Set provider URL to `https://10.0.0.1/api` and `https://192.168.1.1/api`. | `SSRFSecurityError` raised; connection blocked. |
| **ADV-13** | `test_ssrf_rejects_cloud_metadata_endpoint` | `INV-F11-SSRF-08` | Set provider URL to `http://169.254.169.254/latest/meta-data/`. | `SSRFSecurityError` raised; IMDS access blocked. |
| **ADV-14** | `test_ssrf_dns_rebinding_address_pinning` | `INV-F11-SSRF-08` | Mock DNS resolver returning public IP on check, private IP on connect. | Pinning resolved IP forces connection to pre-validated IP; rebinding attempt fails. |
| **ADV-15** | `test_ssrf_redirect_to_private_ip_blocked` | `INV-F11-REDIRECT-09` | Provider returns `302 Location: http://10.0.0.5/internal`. | Redirect target validated; `SSRFSecurityError` raised; redirect chain aborted. |
| **ADV-16** | `test_oversized_response_body_aborts_stream` | `INV-F11-RESPONSE-10` | Provider streams 20MB payload; max response limit = 10MB. | Stream reader aborts at 10MB limit; `ATTEMPT_ERROR_UNKNOWN` recorded; OOM avoided. |
| **ADV-17** | `test_malformed_response_json_failure_classification` | `INV-F11-FAILURE-15` | Provider returns invalid JSON syntax with HTTP 200 OK. | Classified as `ATTEMPT_ERROR_UNKNOWN`; marked non-retryable; state set to `FAILED`. |
| **ADV-18** | `test_secret_credential_isolation_in_attempt_ledger` | `INV-F11-SECRET-13` | Inject exception containing `Authorization: Bearer sk-secret-12345`. | `AIProviderAttemptModel.error_class` stores bounded taxonomy string (`NETWORK_ERROR`); zero secret leakage. |
| **ADV-19** | `test_metrics_cardinality_sanitization` | `INV-F11-METRICS-14` | Send request with dynamic model ID `prompt-injection-tag-999`. | Metric label sanitized to `registered_model_id` or `other`; Prometheus cardinality preserved. |
| **ADV-20** | `test_circuit_breaker_does_not_trip_on_4xx_client_errors` | `INV-F11-FAILURE-15` | Inject 20 consecutive HTTP 400 Bad Request client errors. | Failure classifier marks as client error; circuit state remains `CLOSED`. |
