# ADR-F1-AUDIT: Enterprise Security Audit & Architecture Compliance Verification

## Status
APPROVED (Audit Phase Complete)

## Context
Following the completion of Sprint F1 (REST API implementation), a formal architectural compliance audit was mandated to verify adherence to KarsaSec core design invariants (specifically Invariant L7, R7-R9, R1-R6, and execution safety rules) before initiating Sprint F2.

---

## 1. Security Authority Audit (L7 Compliance Verification)
* **Goal**: Verify that the REST API layer never acts as a security authority. It must never hardcode, override, or calculate a remediation `SECURITY_VERIFIED` verdict.
* **Findings**:
  - `grep -R "VERIFIED_FIXED" karsasec/server` returned **zero** occurrences.
  - The `RemediationService` triggers the E13 `RemediationLifecycleEngine` execution directly and feeds the resulting `RemediationTransactionPackage` into `RTPValidator.validate(rtp)`.
  - The security verification status returned to the client is derived *strictly and exclusively* from `RTPValidationResult.security_verification_status` returned by `RTPValidator`.
  - No database write or REST endpoint overrides this status.

---

## 2. Privacy Boundary Audit (R7-R9 Compliance Verification)
* **Goal**: Ensure no raw source code, patches, diffs, or credentials can escape via the REST endpoints.
* **Findings**:
  - `grep -R "source_code" karsasec/server` and `grep -R "diff" karsasec/server` returned **zero** active data transmission variables. The references are purely structural comments, docstrings, or static config assignments (e.g., `diff_scan=False`).
  - DTO boundaries:
    - `FindingDTO` explicitly maps properties to exclude `evidence.snippet`, `source_code`, or `unified_diff`.
    - `RemediationResponseDTO` and `VerificationReceiptResponseDTO` only contain cryptographic hash commitments and state values, containing no file modifications or raw patch texts.
  - Exception boundaries:
    - Global exception handlers in `karsasec/server/errors.py` catch all exceptions and format them into a generic, structured `APIErrorResponse`.
    - Specific rules in `test_api_security.py` verify that `404` or `500` stack traces do not expose underlying file snippets or system paths to clients.

---

## 3. Determinism Audit
* **Goal**: Validate that all collections (e.g. findings list) maintain deterministic ordering regardless of environment variable configurations (like `PYTHONHASHSEED`).
* **Findings**:
  - `FindingService` implements `list_findings()` with a deterministic multi-key sort:
    ```python
    def _sort_key(self, f: FindingDTO) -> tuple[int, str, int, str]:
        return (
            _severity_rank(f.severity),
            f.file_path,
            f.line_number,
            f.finding_id,
        )
    ```
  - Verification tests in `test_finding_service.py` and `test_api_security.py` validate this sorting stability across independent, sequential REST calls.

---

## 4. Capability Audit
* **Goal**: Confirm that the API package (`karsasec/server/`) contains no execution side effects or shell invocations.
* **Findings**:
  - `grep -R "subprocess"`: **0 matches**
  - `grep -R "os.system"`: **0 matches**
  - `grep -R "eval("`: **0 matches**
  - `grep -R "exec("`: **0 matches**
  - Verified programmatically via automated tests in `test_api_security.py::TestCapabilityAudit`.

---

## 5. Endpoint Threat Model

| Endpoint | Method | Required Scope | Principal Threat | Mitigation |
|---|---|---|---|---|
| `/api/v1/health` | `GET` | *Public* | Information leakage / resource consumption | No internal configuration variables are returned. Zero-allocation response. |
| `/api/v1/scans` | `POST` | `scan:create` | Injected malicious repository paths / Command injection | Strictly validated paths. `_run_scan_pipeline` delegates safely to the AST-walker with no shell execution. |
| `/api/v1/scans/{scan_id}` | `GET` | `scan:read` | Unauthorized access to scan statistics | Scope-guarded access. Scans filtered by Principal authorization rules. |
| `/api/v1/findings` | `GET` | `finding:read` | Information leakage (source/diffs) | Strict DTO mapping excludes all code snippets and context lines. Paginated to prevent memory exhaustion. |
| `/api/v1/remediations` | `POST` | `remediation:create` | Forged approval tokens / unauthorized patch triggers | Enforces strict validation of token ID. Resolves security status solely via `RTPValidator`. |
| `/api/v1/remediations/{transaction_id}/receipt` | `GET` | `receipt:read` | Cryptographic receipt signature tampering | Receipt fingerprint verified by computing SHA-256 over canonicalized JSON representation. |
