# KarsaSec Documentation Hub & Architecture Master Index

Welcome to the **KarsaSec Security Engine Documentation Hub**. This directory contains the complete technical specifications, architectural decision records (ADRs), PRDs, and audit certification reports for the KarsaSec Security Analysis Engine.

---

## 1. Governing Roadmap & Governance Lock

- [FINAL_ROADMAP_LOCK.md](../FINAL_ROADMAP_LOCK.md) — Mandatory governing document locking E9–E21 and V0 Validation Gate.
- [RISK_COVERAGE_MATRIX.md](RISK_COVERAGE_MATRIX.md) — Failure mode to adversarial test coverage mapping.

---

## 2. Structured Directory Hierarchy & Guides

- [`AGENTS.md`](../AGENTS.md) — **Autonomous AI Agent Guide & Codebase Map**.
- [`guides/user_guide.md`](guides/user_guide.md) — **Complete User Guide & CLI Command Reference**.
- [`guides/ai_agent_guide.md`](guides/ai_agent_guide.md) — **AI Agent System Prompt & Execution Guide**.
- [`specs/`](specs/) — Architecture blueprints, PRDs, and technical specifications per sprint (E9–E20).
- [`audit_history/`](audit_history/) — Historical independent verification reports and audit certification logs.
- [`architecture/`](architecture/) — Core ERD and master system blueprints.
- [`contracts/`](contracts/) — Execution contracts and ISR schemas.
- [`guides/`](guides/) — Developer setup and operational usage guides.

---

## 3. Core Governing Documents & Master Index

- [MASTER_PRD.md](MASTER_PRD.md) — Master Product Requirements Document.
- [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md) — Multi-sprint implementation roadmap.
- [PROGRAM_EXECUTION_SPEC.md](PROGRAM_EXECUTION_SPEC.md) — Program execution rules & DAG requirements.
- [AUTONOMOUS_EXECUTION_CHARTER.md](AUTONOMOUS_EXECUTION_CHARTER.md) — Autonomous operations governance charter.
- [e21_internal_readiness_review.md](e21_internal_readiness_review.md) — **Final E21 Internal Readiness Review & Certification Gate**.
- [RISK_COVERAGE_MATRIX.md](RISK_COVERAGE_MATRIX.md) — Failure mode to adversarial test coverage mapping.
- [RULE_COVERAGE_MATRIX.md](RULE_COVERAGE_MATRIX.md) — Vulnerability rule taxonomy coverage matrix.

---

## 4. Upstream Specifications & Historical Audit Reports

- Architectural Specifications: [specs/](specs/) (e.g. `v0_master_prd.md`, `e10_semantic_extractor_architecture.md`, `e17_master_prd.md`, `e20_master_prd.md`).
- Certification Audit Logs: [audit_history/](audit_history/) (e.g. `e14_final_certification.md`, `e16_final_certification.md`, `e20_audit_report.md`).

---

## 5. Acknowledgments & Research Foundation

KarsaSec incorporates conceptual research, taxonomy patterns, and benchmark methodologies derived from pioneering open-source security analysis tools and research repositories:

- **[Semgrep](https://github.com/semgrep/semgrep)** — Structural AST pattern matching, rule syntax ergonomics, and interprocedural taint flow analysis concepts.
- **`sast-skills` & `sast-scan`** — Real-world vulnerability corpus patterns, static analysis benchmarks, and multi-language sink/source taxonomies.
- **`awesome-ai-security-tools` & `static-analysis`** — Open security research indexes and static code analysis paradigms.

We express our sincere gratitude to the global open-source security community, researchers, and maintainers whose work provided invaluable foundation benchmarks and conceptual inspiration for KarsaSec.
