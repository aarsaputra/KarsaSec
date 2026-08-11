# Root Cause Analysis — DVWA Qualification Baseline (Sprint E12-2)

## 1. Executive Summary

During Sprint E12-2, the newly implemented KarsaSec Qualification System was executed against the **DVWA (Damn Vulnerable Web Application)** benchmark target.

The objective was **not** to heuristically alter rules to pass tests, but to establish a deterministic, trustworthy, reproducible security accuracy baseline and perform a quantitative root-cause analysis of False Positives (FP) and False Negatives (FN).

### Global Accuracy Baseline

| Metric | Value | Rationale |
| :--- | :--- | :--- |
| **Total Benchmark Cases** | **30** | 20 True Positive (TP) expectations, 10 True Negative (TN) expectations |
| **True Positives (TP)** | **12** | Core vulnerability sinks matched accurately |
| **False Positives (FP)** | **272** | 3 FP-from-TN + 269 unmatched findings from broad rule patterns |
| **False Negatives (FN)** | **8** | Vulnerabilities missed due to taint/constant resolution limits |
| **True Negatives (TN)** | **7** | Safe static inclusion patterns correctly suppressed |
| **UNKNOWN Findings** | **0** | No findings emitted with UNKNOWN confidence |
| **Global Precision** | **4.23%** | Low precision driven by AST-less / lexical rule matches |
| **Global Recall** | **60.00%** | 12 out of 20 vulnerable cases detected |
| **Global F1 Score** | **7.89%** | Baseline harmonic mean |
| **Exact Duplicate Rate** | **0.00%** | Deduplication engine successfully eliminated duplicate findings |
| **Cross-Rule Overlap Rate** | **31.46%** | 67 locations triggered multiple rules |

---

## 2. Per-Category Breakdown

| Category | TP | FP | FN | TN | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **PATH_TRAVERSAL** | **4** | **0** | **0** | **0** | **100.0%** | **100.0%** | **100.0%** |
| **SQL_INJECTION** | **5** | **0** | **2** | **2** | **100.0%** | **71.4%** | **83.3%** |
| **LFI** | **3** | **3** | **1** | **3** | **50.0%** | **75.0%** | **60.0%** |
| **COMMAND_INJECTION** | **0** | **0** | **4** | **2** | **0.0%** | **0.0%** | **0.0%** |
| **CRYPTOGRAPHIC_FAILURES** | **0** | **0** | **1** | **0** | **0.0%** | **0.0%** | **0.0%** |
| **OTHER (Auxiliary Rules)** | **0** | **269** | **0** | **0** | **0.0%** | **0.0%** | **0.0%** |

---

## 3. Root-Cause Classification

### 3.1 False Positives (FP: 272 findings)

1. **`LEXICAL_SNIPPET_MATCH` (212 findings / 77.9% of FPs)**:
   - **`KS-OWASP-0007` (56 FPs)**, **`KS-PHP-0003` (27 FPs)**, **`KS-PHP-CRYPTO-0001` (23 FPs)**:
   - *Cause*: Heuristic regex rules matching string keywords in non-vulnerable contexts (e.g. comments, HTML headers, safe helper functions).
   - *Remediation*: Require AST symbol resolution and taint propagation before emitting findings.

2. **`UNCONSTRAINED_AUXILIARY_RULES` (57 findings / 21.0% of FPs)**:
   - **`KS-PHP-AUTH-0001` (19 FPs)**, **`KS-OWASP-0010` (19 FPs)**, **`KS-OWASP-0001` (12 FPs)**:
   - *Cause*: Rules triggering on generic superglobals (`$_GET`, `$_POST`) without verifying whether the value flows into a dangerous sink.

3. **`FALSE_POSITIVE_FROM_TN` (3 findings / 1.1% of FPs)**:
   - *Cause*: Static include constant `DVWA_WEB_PAGE_TO_ROOT` matching broad LFI pattern in `vulnerabilities/fi/index.php`.

---

### 3.2 False Negatives (FN: 8 cases)

1. **`COMMAND_INJECTION_TAINT_MISS` (4 FN cases)**:
   - **Cases**: `dvwa-exec-low-001`, `dvwa-exec-low-002`, `dvwa-exec-medium-001`, `dvwa-exec-medium-002` (`vulnerabilities/exec/source/low.php`, `medium.php`).
   - *Cause*: `shell_exec('ping ' . $target)` receives `$target` which is assigned from `$_REQUEST['ip']`. Current rule matches `shell_exec($_GET[...])` directly but fails when variable assignment occurs across separate AST nodes.
   - *Architecture Gap*: Requires **Interprocedural & Intraprocedural Taint Flow Resolution** (Sprint E11).

2. **`SQL_INJECTION_MULTI_PATH_MISS` (2 FN cases)**:
   - **Cases**: `dvwa-sqli-medium-001`, `dvwa-sqli-blind-low-001`.
   - *Cause*: Taint flow passes through SQLite connection `$sqlite_db_connection->query($query)` or `$id` sanitized on MySQL path but left raw on SQLite path.

3. **`LFI_ENVIRONMENT_TAINT_MISS` (1 FN case)**:
   - **Case**: `dvwa-fi-source-lfi-001`.
   - *Cause*: Variable `$file = $_GET['page']` used in `include($file)`.

4. **`WEAK_CRYPTO_CONTEXT_MISS` (1 FN case)**:
   - **Case**: `dvwa-brute-crypto-001`.
   - *Cause*: `md5($pass)` matched as weak crypto, but rule expected specific rule ID `KS-OWASP-0002` matching password hashing context.

---

## 4. Architectural Next Steps & Roadmap Impact

1. **Anti-Circularity Invariant**: Ground truth manifest remains untouchable and authoritative.
2. **Sprint E11 Integration**: The 4 Command Injection FNs and 2 SQLi FNs define the exact requirements for E11 Data-Flow & Taint Analysis.
3. **Rule Hardening**: The 269 auxiliary FPs prove that AST-less regex rules must be migrated to AST-backed node evaluation.
