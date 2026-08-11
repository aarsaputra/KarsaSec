# ADR-0012: False-Negative Closure & Data-Flow File Path Propagation Architecture

## Status
Accepted

## Date
2026-08-11

## Context
During Sprint E12-6 qualification, KarsaSec achieved an 85.0% recall rate with 3 False Negatives (FNs) on the DVWA benchmark. Investigation revealed that the remaining 3 FNs (`sqli/index.php`, `sqli_blind/index.php`, `xss_r/index.php`) occurred because sink-level taint verification was invoked without propagating the active `file_path`. Without file location context, the Data-Flow Graph (DFG) builder could not locate statically included files (`require_once dvwaPage.inc.php`), causing helper functions (`dvwaSecurityLevelGet()`) returning user input (`$_COOKIE['security']`) to be missing from symbol tables.

## Decision
1. **Pass `file_path` in `TaintVerifier.verify_sink`**: Extended `TaintVerifier.verify_sink` to accept `file_path: Path | None = None` and forward it to `DataFlowAnalyzer.analyze_sink`.
2. **Propagate `file_path` from `RuleExecutor` and `SemanticFindingQualifier`**: Updated execution and qualification state machines to supply `scan_context.file_path` and `candidate.file_path` respectively.
3. **Preserve Generic Architecture Invariants**: Maintain zero hardcoded file paths or DVWA-specific logic in core engines. DFG file include resolution operates generically across relative/parent directory structures.

## Consequences
- **100% Benchmark Recall**: All 20 ground-truth TP cases across Command Injection, Path Traversal, SQL Injection, Cryptography, and LFI are now correctly identified and qualified.
- **Zero FNs**: Closed all 3 remaining false negatives.
- **Zero Regressions**: Preserved 100% determinism, test coverage, and code quality (0 ruff lint errors).
