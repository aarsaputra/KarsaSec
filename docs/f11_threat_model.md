# Sprint F11 — Threat Model: AI Gateway Resilience & Provider Execution Security

**Date**: 2026-08-20  
**Target Architecture**: KarsaSec External AI Provider Execution Boundary  
**Scope**: Provider execution, timeout isolation, retry safety, circuit breaker, distributed rate limiting, SSRF protection, and resource exhaustion defense.

---

## 1. Threat Actors & Capabilities

| Actor ID | Threat Actor | Attacker Capability & Vectors |
| :---: | :--- | :--- |
| **TA-1** | Malicious Tenant | Controls prompt payloads, attempt IDs, metadata, and request rates via external API endpoints. |
| **TA-2** | Compromised API Client | Compromised bearer tokens sending rapid-fire, malformed, or oversized requests. |
| **TA-3** | Malicious Provider Endpoint | Rogue/impersonated AI endpoint returning malicious payloads, infinite streams, or HTTP redirects. |
| **TA-4** | Compromised Provider | Legitimate provider returning 5xx storms, HTTP 429 rate limits, or credentials in error bodies. |
| **TA-5** | Malicious Worker | Rogue worker attempting stale task resumption, double budget releases, or state bypasses. |
| **TA-6** | Stale Worker | Slow/partitioned worker waking up post-lease expiration to write outdated execution results. |
| **TA-7** | Concurrent Workers | Multiple workers racing to execute the same request or claim provider concurrency slots. |
| **TA-8** | Network Attacker | Man-in-the-middle / DNS spoofer attempting DNS rebinding or redirect-based SSRF. |
| **TA-9** | Provider Outage | External API cascading failure triggering retry storms and worker thread pool exhaustion. |
| **TA-10** | Retry Storm | Amplified retries multiplying $N \times M$ requests, exhausting provider quotas and DB connections. |
| **TA-11** | Resource Exhaustion Attacker | Sends slowloris HTTP responses, infinite response streams, or high-cardinality metric values. |

---

## 2. Threat Analysis & Vulnerability Matrix

### 2.1 Server-Side Request Forgery (SSRF) & Endpoint Exploitation

#### T-F11-SSRF-01: Direct Private IP & Loopback Target Access
- **Attack Precondition**: Tenant specifies custom provider endpoint or provider configuration contains dynamic URLs.
- **Attacker Path**: `https://127.0.0.1/admin`, `http://169.254.169.254/latest/meta-data/`, `http://10.0.0.1/`.
- **Security Impact**: Critical credential theft, cloud metadata exposure, internal service compromise.
- **Current Mitigation**: None (MISSING). Endpoint URL is passed directly to HTTP client.
- **Recommended Control**: `EndpointSecurityPolicy` enforcing strict protocol (HTTPS only), IP range blacklisting (RFC 1918, RFC 3927, loopback, multicast, link-local), and pre-flight socket address resolution validation.

#### T-F11-SSRF-02: DNS Rebinding & TOCTOU Resolution Bypass
- **Attack Precondition**: Attacker controls DNS server for `attacker-provider.com` with TTL=0 returning public IP first, then `169.254.169.254`.
- **Attacker Path**: Initial URL validation resolves to public IP; HTTP client connect phase resolves to AWS metadata IP.
- **Security Impact**: Bypasses static URL validation, exposing internal AWS/GCP metadata.
- **Recommended Control**: Pin resolved IP address at validation time or enforce custom transport resolver pinning resolved socket address before HTTP connect phase.

#### T-F11-SSRF-03: HTTP Redirect SSRF Bypass
- **Attack Precondition**: Provider returns `HTTP 302 Found` to `http://169.254.169.254/`.
- **Attacker Path**: Initial request passes public endpoint filter; HTTP client auto-follows redirect to forbidden target.
- **Security Impact**: SSRF filter bypass via HTTP redirects.
- **Recommended Control**: Disable auto-redirects in HTTP client, or re-evaluate `EndpointSecurityPolicy` on every HTTP redirect hop with maximum redirect limit of 3.

---

### 2.2 Provider Execution & Resilience Attacks

#### T-F11-RES-01: Unbounded Execution Timeout & Worker Exhaustion (Slowloris)
- **Attack Precondition**: Malicious or degraded provider hangs TCP connection or sends 1 byte/sec response.
- **Attacker Path**: Provider keeps HTTP connection open indefinitely; worker thread pool starves.
- **Security Impact**: System-wide Denial of Service (DoS); workers blocked forever.
- **Current Mitigation**: `ATTEMPT_ERROR_TIMEOUT` class exists, but per-attempt hard wall-clock timeout is missing.
- **Recommended Control**: Hard per-attempt timeout wrapper (`asyncio.wait_for` / socket timeout) and total request elapsed time ceiling.

#### T-F11-RES-02: Retry Storm & Request Amplification Explosion
- **Attack Precondition**: Provider returns 503 Service Unavailable under load.
- **Attacker Path**: 100 concurrent workers retry failed requests 5 times without backoff/jitter $\rightarrow$ 500 requests/sec.
- **Security Impact**: Provider quota exhaustion, API rate-limit bans, database transaction pool exhaustion.
- **Recommended Control**: Exponential backoff with Full Jitter, hard upper bound on total attempts ($N_{max} \le 3$), and circuit breaker trip on error rate threshold.

#### T-F11-RES-03: Circuit Breaker Poisoning & State Manipulation
- **Attack Precondition**: Malicious tenant sends malformed requests designed to trigger 4xx errors.
- **Attacker Path**: Malformed requests increment provider error counter, tripping circuit breaker to OPEN for legitimate traffic.
- **Security Impact**: Denial of Service for valid tenant requests via provider lockout.
- **Recommended Control**: Failure classifier distinguishing client errors (HTTP 400/401/403/422 - non-retryable, non-circuit-tripping) from provider infrastructure errors (HTTP 500/502/503/504, connection drop, timeout).

#### T-F11-RES-04: Distributed Rate Limit Bypass & Race Condition
- **Attack Precondition**: Multiple workers execute requests against provider concurrently.
- **Attacker Path**: 50 workers query local rate limit counter simultaneously before incrementing, bypassing quota.
- **Security Impact**: Provider API ban, unexpected financial overage charges.
- **Recommended Control**: Atomic Lua script / Redis token bucket or PostgreSQL atomic CAS counter increment.

#### T-F11-RES-05: Oversized Response & Memory Exhaustion Attack
- **Attack Precondition**: Malicious or compromised provider streams 10GB payload response.
- **Attacker Path**: Worker buffers entire response body into memory $\rightarrow$ Out-Of-Memory (OOM) process crash.
- **Security Impact**: Worker process crash, Denial of Service.
- **Recommended Control**: Hard response body byte limit (e.g. max 10MB) enforced via streaming chunk reader abort.

---

### 2.3 Secret Isolation & Observability Security

#### T-F11-SEC-01: Provider Credential Leakage in Error Logs & Traces
- **Attack Precondition**: HTTP client error includes full request headers or raw exception string containing `Authorization: Bearer sk-secret...`.
- **Attacker Path**: Exception string stored in `AIProviderAttemptModel.error_class` or logged to stdout.
- **Security Impact**: Critical API key leakage, unauthorized provider resource access.
- **Current Mitigation**: `KNOWN_ERROR_CLASSES` taxonomy restricts error strings to fixed enum values.
- **Recommended Control**: Enforce zero raw exception payloads in storage; sanitize all headers/URLs before logging; mask secrets in traces.

#### T-F11-SEC-02: Metrics Cardinality Explosion Attack
- **Attack Precondition**: Attacker supplies randomized model IDs or custom error strings in API requests.
- **Attacker Path**: Prometheus metrics label `model_id="prompt-inj-xyz-123..."` generates millions of time series.
- **Security Impact**: Prometheus memory exhaustion, monitoring system crash.
- **Recommended Control**: Sanitize metric label values against strict allowlist of registered `provider_id` and `model_id` values.

---

## 3. Threat Summary & Severity Matrix

| Threat ID | Threat Name | Affected Component | Security Severity | Recommended Control |
| :---: | :--- | :--- | :---: | :--- |
| **T-F11-SSRF-01** | Direct Private IP SSRF | `HTTPClient` / Router | **CRITICAL** | `EndpointSecurityPolicy` IP Range Filter |
| **T-F11-SSRF-02** | DNS Rebinding Bypass | `HTTPClient` | **HIGH** | Resolved Socket Address Pinning |
| **T-F11-SSRF-03** | Redirect-based SSRF | `HTTPClient` | **HIGH** | Max 3 Redirects & Per-Hop Re-Validation |
| **T-F11-RES-01** | Slowloris / Timeout DoS | Worker Execution | **HIGH** | Hard Per-Attempt Timeout Guard |
| **T-F11-RES-02** | Retry Storm Amplification | Retry Engine | **HIGH** | Exponential Backoff + Jitter + Cap |
| **T-F11-RES-03** | Circuit Breaker Poisoning | Circuit Breaker | **MEDIUM** | Failure Classification (Client vs Server) |
| **T-F11-RES-04** | Rate Limit Race Bypass | Rate Limiter | **HIGH** | Atomic CAS / Redis Token Bucket |
| **T-F11-RES-05** | Oversized Response OOM | Provider Response | **HIGH** | Max Response Body Byte Limit (10MB) |
| **T-F11-SEC-01** | Credential Leakage | Logging / Storage | **CRITICAL** | Bounded Taxonomy + Masking |
| **T-F11-SEC-02** | Metrics Cardinality DoS | Observability | **MEDIUM** | Label Allowlist Sanitization |
