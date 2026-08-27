# K1 Semantic Ground-Truth Realization Report (INV-G5.4.13 & INV-G5.4.15)

## 1. Ground-Truth Realization Audit
- **Requirement**: Every case MUST contain executable/static-analysis-relevant source code representing declared properties (`expected_property`, `expected_status`, `expected_cwe`, `category`).
- **Pass Stub Elimination**: 100% of trivial `def handler(req): pass` stubs have been eliminated. All 40 cases feature real Python/Flask/Django/FastAPI style code.
- **Oracle Verification**: Decoupled `analyze_fixture()` independently inspected all 40 fixtures without label leakage and confirmed AST/semantic evidence.

---

## 2. Vulnerability & Safe Control Distribution (Exact 40-Case Audit)

| Vulnerability Family | Total Cases | Vulnerable Fixtures (TP) | Safe Controls (TN) | Dev (50%) | Val (25%) | Holdout (25%) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **JWT** | 14 | 9 | 5 | 8 | 3 | 3 |
| **OAuth** | 10 | 6 | 4 | 6 | 3 | 1 |
| **Business Logic** | 16 | 10 | 6 | 6 | 4 | 6 |
| **Total** | **40** | **25** | **15** | **20** | **10** | **10** |
