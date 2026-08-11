# KarsaSec Sprint E12-7 False-Negative Taxonomy & Closure Analysis

## Executive Summary

Sprint E12-7 achieved **100% overall recall** across all DVWA benchmark vulnerability categories (up from 85.0% in E12-6), successfully closing all 3 remaining False-Negative (FN) cases without introducing regressions or hardcoded benchmark shortcuts.

## Summary of Closed False Negatives

| Case ID | Location | Vulnerability Class | Root Cause | Resolution |
| :--- | :--- | :--- | :--- | :--- |
| `dvwa-sqli-index-lfi-001` | `vulnerabilities/sqli/index.php:34` | LFI | `file_path` missing in `TaintVerifier.verify_sink` call during qualification, preventing static include resolution for `dvwaPage.inc.php`. | Forwarded `file_path` through `RuleExecutor`, `TaintVerifier`, and `SemanticFindingQualifier` to `DataFlowAnalyzer`. |
| `dvwa-sqli-blind-index-lfi-001` | `vulnerabilities/sqli_blind/index.php:34` | LFI | Missing `file_path` context in `verify_sink` truncated multi-branch taint tracking for `$vulnerabilityFile`. | Provided full `file_path` context to DFG builder to parse helper function definitions (`dvwaSecurityLevelGet()`). |
| `dvwa-xss-r-index-lfi-001` | `vulnerabilities/xss_r/index.php:32` | LFI | Taint verifier dismissed sink as static due to missing DFG symbol table for included helper functions. | Extended `file_path` context to resolve included page structures, correctly identifying `$_COOKIE['security']` taint propagation. |

## Technical Architectural Fix

### Root Cause Mechanics
The KarsaSec static analysis pipeline utilizes incremental data-flow graph (DFG) construction to trace untrusted inputs across function calls and control-flow branches. When `TaintVerifier.verify_sink` was invoked by `RuleExecutor` and `SemanticFindingQualifier`, the active `file_path` was omitted.

Without `file_path`, the DFG builder could not locate or parse statically included files (e.g., `require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php'`). As a result:
1. Function definitions such as `dvwaSecurityLevelGet()` were absent from the DFG symbol table.
2. Variable assignments inside multi-branch `switch` statements (`$vulnerabilityFile = 'low.php'`) appeared un-tainted.
3. Sink verification classified the `require_once` argument as `STATIC_INPUT`, leading to false negatives.

### Architectural Hardening
1. **`TaintVerifier.verify_sink`**: Updated signature to accept `file_path: Path | None = None` and forward it directly to `DataFlowAnalyzer.analyze_sink`.
2. **`RuleExecutor.execute_scan`**: Updated evidence verification step to pass `scan_context.file_path`.
3. **`SemanticFindingQualifier.qualify_candidate`**: Updated qualification pipeline to pass `candidate.file_path` into `verify_sink`.

## Verification & Invariant Audit
- **Zero FN**: FN count reduced from 3 to 0.
- **100% Recall**: Achieved 100% recall across Command Injection, Path Traversal, SQL Injection, Cryptography, and LFI.
- **Determinism**: Verified 100% deterministic output (`diff -u run1.json run2.json` produced exit code 0).
