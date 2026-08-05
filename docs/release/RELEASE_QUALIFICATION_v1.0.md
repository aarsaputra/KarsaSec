# KarsaSec Release Qualification Checklist v1.0

## Overview
Dokumen ini mendefinisikan **quality gates wajib** yang harus dilalui sebelum setiap rilis KarsaSec. Jika satu gate gagal, rilis **DIBLOKIR** sampai diperbaiki.

---

## Pre-Release Quality Gates

### Gate 1 — Unit Tests
```
Command  : python3 -m pytest tests/unit/ -v
Criteria : 100% pass rate, 0 failures, 0 errors
Status   : [ ]
```

### Gate 2 — Qualification Tests (Artifact Validation)
```
Command  : python3 -m pytest tests/qualification/test_artifact_validator.py -v
Criteria : All invariant validators pass (AST, CFG, CallGraph, Dataflow, Findings)
Status   : [ ]
```

### Gate 3 — Deterministic Scan (100-Run)
```
Command  : python3 -m pytest tests/qualification/test_benchmark_determinism.py -v
Criteria : SHA-256 fingerprint hash identical across 100 consecutive runs
Status   : [ ]
```

### Gate 4 — Fault Injection & Crash Isolation
```
Command  : python3 -m pytest tests/qualification/test_fault_injection.py -v
Criteria : All crash scenarios isolated; pipeline continues after failures
Status   : [ ]
```

### Gate 5 — API Stability Verification
```
Command  : python3 -c "from karsasec.core.api_stability import api_stability_verifier; changes = api_stability_verifier.verify_api_stability(); print('PASS' if not changes else changes)"
Criteria : Zero breaking changes vs frozen API snapshot
Status   : [ ]
```

### Gate 6 — Golden Test / Security Corpus Validation
```
Command  : python3 -m pytest tests/unit/rules/test_corpus_validation.py -v
Criteria : All security corpus samples (Python, JS, Go, PHP, Docker, K8s, GHA) pass
Status   : [ ]
```

### Gate 7 — SARIF Output Validation
```
Command  : python3 -m karsasec.cli.main scan <target> --format sarif -o output.sarif && python3 -c "import json; d=json.load(open('output.sarif')); assert d['version']=='2.1.0'"
Criteria : Valid SARIF v2.1.0 JSON schema output
Status   : [ ]
```

### Gate 8 — Documentation Integrity
```
Criteria : All 8 contract docs exist in docs/contracts/
         : PLATFORM_COMPATIBILITY_MATRIX.md exists
         : CAPABILITY_INTEGRATION_MATRIX.md exists
         : All 5 ADRs present in docs/adr/
Status   : [ ]
```

### Gate 9 — Performance Baseline
```
Criteria : Single-file scan < 50ms
         : 100-file directory scan < 2000ms
         : Memory usage < 200MB peak
Status   : [ ]
```

### Gate 10 — Regression Test (Full Suite)
```
Command  : python3 -m pytest tests/ -v
Criteria : 100% pass rate across ALL test suites (unit + qualification)
Status   : [ ]
```

---

## Release Blocking Policy

> **Jika satu gate gagal, rilis v1.0 DIBLOKIR.**

Pemilik gate harus memperbaiki kegagalan dan menjalankan ulang seluruh checklist sebelum rilis disetujui.

---

## Version Tagging
```
Format : v1.0.0-rc.{N}  →  v1.0.0
Branch : release/v1.0
Tag    : git tag -s v1.0.0 -m "KarsaSec v1.0.0 Production Release"
```
