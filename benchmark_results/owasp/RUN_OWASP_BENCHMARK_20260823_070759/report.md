==================================================
KARSASEC G5 EXTERNAL VALIDITY BASELINE
==================================================

Commit: cbbb7fe4d088cd55212e97fe7928847103892d97
Dataset: OWASP_BENCHMARK
Dataset Version: v1.2
Configuration Hash: CONFIG_FREEZE_V1
Dirty Worktree Clean: False

Total Cases: 70
TP: 29
FP: 0
TN: 32
FN: 0
UNKNOWN: 9
CONFLICT: 0

Strict Precision: 1.0000
Strict Recall: 0.8286
Epistemic Recall: 1.0000
F1 Score: 0.9062
Epistemic Uncertainty Ratio: 0.1286

95% Confidence Intervals (Wilson Score):
Precision CI: [0.8830, 1.0000]
Recall CI: [0.6732, 0.9190]
Epistemic Recall CI: [0.9011, 1.0000]

--------------------------------------------------
LANGUAGE × FRAMEWORK
--------------------------------------------------
java / servlet: Recall 0.8286

--------------------------------------------------
ERROR FORENSICS & TAXONOMY
--------------------------------------------------
FN_FRAMEWORK: 6
UNRESOLVED_WRAPPER: 3

--------------------------------------------------
TOP FAILURE MODES
--------------------------------------------------
1. BenchmarkTest00017 (CWE-78) -> Stage: SOURCE_RESOLUTION | Root Cause: Framework request wrapper unresolved by D1 pass
2. BenchmarkTest00018 (CWE-78) -> Stage: DECISION | Root Cause: Unresolved custom sanitization wrapper
3. BenchmarkTest00019 (CWE-78) -> Stage: SOURCE_RESOLUTION | Root Cause: Framework request wrapper unresolved by D1 pass
4. BenchmarkTest00037 (CWE-22) -> Stage: SOURCE_RESOLUTION | Root Cause: Framework request wrapper unresolved by D1 pass
5. BenchmarkTest00038 (CWE-22) -> Stage: DECISION | Root Cause: Unresolved custom sanitization wrapper

--------------------------------------------------
MUTATION VALIDATION
--------------------------------------------------
Killed: 3
Survived: 1
Invalid: 0
Inconclusive: 0
Mutation Score: 0.7500

Surviving Mutant Analysis:
  - MUT-AUTH-001: Engine verdict remained insensitive (VULNERABLE) after semantic mutation

--------------------------------------------------
ARCHITECTURAL VERDICT
--------------------------------------------------
G5-1 Readiness Audit: PASS
G5-2 OWASP Baseline: COMPLETED
G5-3 Error Forensics: COMPLETED
G5-4 Mutation Validation: COMPLETED

Overall Gate 5 Verdict: G5_PASS_WITH_KNOWN_GAPS
==================================================