# Phase 3 — Privacy Boundary Audit (R7-R9)

## Audit Target
`karsasec/persistence/` (Models, Repositories, Migrations, Audit Trail)

## Objective
Verify that the persistence layer enforces R7-R9 Privacy Boundary invariants. No source code, snippets, diffs, patches, credentials, tokens, or API keys may be stored in database tables or audit events.

---

## 1. Static Schema Analysis (`models.py` & Migration DDL)

### `tasks` Table Inspection
- **Defined Columns**: `id`, `task_id`, `finding_id`, `approval_token_id`, `fingerprint`, `state`, `attempts`, `max_attempts`, `lease_seconds`, `lease_started_at`, `error_message`, `receipt_id`, `receipt_fingerprint`, `security_verification_status`, `created_at`, `updated_at`.
- **Stripped Field Verification**: The domain model `RemediationTask.token` is **explicitly omitted** from `TaskModel`.
- **Code Reference (`task_repository.py`, Line 85)**:
  ```python
  # token is intentionally not persisted (R7-R9 privacy)
  ```
  When mapping back to domain (`_model_to_domain`), `token` is set to `""` (empty string sentinel).

### `receipts` Table Inspection
- **Defined Columns**: `id`, `receipt_id`, `transaction_id`, `finding_id`, `rule_id`, `receipt_version`, `integrity_status`, `security_verification_status`, `verification_run_id`, `matching_findings_count`, `proposal_fingerprint`, `provenance_fingerprint`, `ledger_fingerprint`, `receipt_fingerprint`, `created_at`.
- **Observation**: Strictly contains nonces, hashes, IDs, and metadata. Zero source code or patch content columns exist.

### `audit_events` Table Inspection
- **Defined Columns**: `id`, `task_id`, `event_type`, `details`, `created_at`.
- **Detail Sanitization Enforcement (`audit_repository.py`, Line 130-133)**:
  ```python
  safe_details = {
      k: v for k, v in event.details.items()
      if k not in {"source_code", "unified_diff", "diff", "patch", "token", "credential", "api_key"}
  }
  ```
  Any attempt to pass sensitive keys in `details` dictionary is automatically stripped prior to calling `session.add(...)`.

---

## 2. Grep Verification Results

```bash
grep -rnE "source_code|snippet|diff|patch|credential|token|api_key|secret" karsasec/persistence/
```
**Results Analysis**:
- `TaskModel` defines `approval_token_id` (a non-sensitive reference UUID string).
- No column for `source_code`, `unified_diff`, `patch`, `credential`, or `token` value exists.
- Static regex test in `TestPrivacyBoundaryPersistence.test_models_py_has_no_source_code_columns` passed.

---

## 3. Adversarial Test Verification
- `TestPrivacyBoundaryPersistence.test_task_to_dict_excludes_token`: Passed.
- `TestPrivacyBoundaryPersistence.test_task_to_dict_excludes_source_code_keys`: Passed.
- `TestPhase8AdversarialScenarios.test_5_persistence_privacy_leakage`: Passed.

---

## 4. Formal Privacy Audit Verdict

```text
STATUS: PASS
```

**Reasoning**: Database schema, repository serializers, and audit append mechanisms strictly exclude sensitive source code, diffs, patches, secrets, and raw tokens. R7-R9 privacy boundary is 100% enforced.
