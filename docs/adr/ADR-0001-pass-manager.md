# ADR-0001: Analysis Pass Manager Contract Architecture

* **Status:** Accepted
* **Date:** 2026-08-05
* **Authors:** KarsaSec Core Platform Architecture Team

## Context

Static code analysis engines require executing diverse processing steps (AST Parsing, Semantic Resolution, IR Construction, CFG Building, CallGraph Analysis, Taint Propagation, and Rule Matching). In initial designs, passes directly called each other, introducing tight coupling and execution rigidity.

## Decision

We introduce the **Analysis Pass Manager (`karsasec/runtime/pass_manager.py`)**. Each processing step is implemented as an independent `AnalysisPass` declaring explicit input artifacts, output artifacts, required capabilities, and time/memory execution budgets.

## Consequences

### Positive
- Modular pass isolation enabling lazy pass execution via runtime DAG planning.
- Failure isolation: errors in one pass do not crash unrelated language passes.
- Standardized execution telemetry (time and memory profiling).

### Negative
- Mild registration overhead per pass.
