# KarsaSec Sprint F1 Enterprise REST API Architecture

**Version**: 1.0  
**Status**: Architectural Specification (Sprint F1)  
**Base Path**: `/api/v1/`  

---

## 1. Executive Overview

The **Enterprise REST API Layer (`karsasec.server`)** acts as an HTTP adapter layer around the established KarsaSec core security engine (E13 Remediation Lifecycle Engine & F0 Remediation Transaction Package system). 

### Core Architectural Principle: **API != Security Authority**
The REST API is strictly forbidden from making security claims, determining patch validity, or generating verification statuses on its own. All security state transitions and verification statuses are produced exclusively by the underlying E13 `RemediationLifecycleEngine` and validated through F0 `RTPValidator` contracts.

---

## 2. System Architecture & Request Processing Topology

```text
                    ┌──────────────────────┐
                    │  Enterprise Client   │
                    └──────────┬───────────┘
                               │ HTTP / JSON
                               ▼
                    ┌──────────────────────┐
                    │     FastAPI App      │
                    │      /api/v1/*       │
                    └──────────┬───────────┘
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
   Request Correlation                  Security Middleware
   (X-Request-ID Header)               (AuthN & AuthZ Boundary)
            │                                     │
            └──────────────────┬──────────────────┘
                               ▼
                     Request DTO Validation
                               │
                               ▼
                   Application Service Layer
            (ScanService / FindingService / RemediationService)
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
         Scan Engine        Findings      E13 Lifecycle Engine
      (RuleExecutor)     Correlator &          │
                          Qualifier            ▼
                                        VerificationResult
                                               │
                                               ▼
                                         F0 RTP Builder
                                               │
                                               ▼
                                         RTP Validator
                                               │
                              ┌────────────────┴───────────────┐
                              │                                │
                              ▼                                ▼
                       Integrity VALID                 Integrity INVALID
                              │                                │
                              ▼                                ▼
                   Fresh Verification?                 NOT VERIFIED
                              │
                    ┌─────────┴─────────┐
                    │                   │
                   YES                  NO
                    │                   │
                    ▼                   ▼
             VERIFIED_FIXED        NOT VERIFIED
             + 0 findings
                    │
                    ▼
             SECURITY_VERIFIED
                    │
                    ▼
             VerificationReceipt
                    │
                    ▼
               Response DTO / JSON
```

---

## 3. Module Layout (`karsasec/server/`)

```text
karsasec/server/
├── __init__.py
├── app.py                     # FastAPI application factory & lifespan
├── config.py                  # API server configuration settings
├── dependencies.py            # FastAPI Dependency Injection providers
├── middleware.py              # X-Request-ID, security, error middleware
├── errors.py                  # Uniform API error handlers & response model
├── security/
│   ├── __init__.py
│   ├── authentication.py     # AuthenticationProvider & Principal resolution
│   ├── authorization.py      # Action/Resource permission checking
│   └── models.py             # Security principal & scope dataclasses
├── api/
│   └── v1/
│       ├── __init__.py
│       ├── router.py          # Master v1 APIRouter aggregator
│       ├── health.py          # /api/v1/health endpoint
│       ├── scans.py           # /api/v1/scans endpoints
│       ├── findings.py        # /api/v1/findings endpoints
│       ├── remediation.py     # /api/v1/remediations endpoints
│       └── receipts.py        # /api/v1/remediations/{id}/receipt endpoint
├── dto/
│   ├── common.py              # Base DTOs & API error model
│   ├── scan.py                # Scan request/response DTOs
│   ├── finding.py             # Finding list/detail DTOs
│   ├── remediation.py         # Remediation trigger/status DTOs
│   └── receipt.py             # Receipt response DTOs
└── services/
    ├── scan_service.py        # Scan execution service
    ├── finding_service.py     # Finding retrieval service
    ├── remediation_service.py # E13/F0 remediation lifecycle adapter service
    └── receipt_service.py     # Receipt retrieval service
```

---

## 4. API Endpoints Specification

| Method | Endpoint | Description | Security Scope |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | System health check (zero internal detail exposure) | Public / None |
| `POST` | `/api/v1/scans` | Execute deterministic SAST scan | `scan:create` |
| `GET` | `/api/v1/scans/{scan_id}` | Retrieve scan result summary | `scan:read` |
| `GET` | `/api/v1/findings` | List/filter findings with stable ordering | `finding:read` |
| `GET` | `/api/v1/findings/{finding_id}` | Retrieve single finding details | `finding:read` |
| `POST` | `/api/v1/remediations` | Trigger E13 lifecycle remediation transaction | `remediation:create` |
| `GET` | `/api/v1/remediations/{transaction_id}` | Retrieve remediation transaction status | `remediation:read` |
| `GET` | `/api/v1/remediations/{transaction_id}/receipt` | Retrieve F0 `VerificationReceipt` payload | `receipt:read` |

---

## 5. Security & Privacy Boundary Guarantees

1. **Zero LLM Authority**: Security verification status (`SECURITY_VERIFIED`) is computed strictly via:
   $$\text{SecurityVerified} = (I = \text{VALID}) \land (V = \text{VALID}) \land (S = \text{VERIFIED\_FIXED}) \land (M = 0)$$
   where $I$ is RTP integrity, $V$ is verification freshness/contract, $S$ is SAST verification status, and $M$ is remaining matching findings count.
2. **Payload Privacy Boundary**: DTOs and API responses MUST NOT include raw source code (`source_code`), raw unified diff hunks (`unified_diff`, `diff`), passwords, secrets, API keys, or access tokens.
3. **Deterministic Ordering**: All collection endpoints (e.g. `/api/v1/findings`) return results sorted by an explicit, stable tuple `(severity_rank, file_path, line_number, finding_id)` to ensure determinism across requests.
