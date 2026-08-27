<p align="center">
  <img src="img/KarsaSec.webp" alt="KarsaSec Banner" width="100%">
</p>

<h1 align="center">🛡️ KarsaSec</h1>

<p align="center">
  <strong>Next-Generation Multi-Language AST Security Analysis Engine & Autonomous SecOS</strong>
</p>

<p align="center">
  <a href="https://github.com/aarsaputra/KarsaSec"><img src="https://img.shields.io/badge/Status-E9--E21%20Internal%20Readiness%20Certified-brightgreen?style=for-the-badge" alt="Status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python"></a>
  <a href="docs/README.md"><img src="https://img.shields.io/badge/V0--E21-Certified-orange?style=for-the-badge" alt="V0-E21 Certified"></a>
</p>

---

## 🇮🇩 / 🇬🇧 Philosophy & Meaning of "KarsaSec"

> **Karsa** *(Ancient Kawi / Sanskrit / Indonesian)*: **Noble Intent, Strong Will, High Aspirations, and Soulful Creative Power**.

### 🇮🇩 Bahasa Indonesia
**KarsaSec** melambangkan **"Kehendak Luhur & Tekad Kuat untuk Membangun Benteng Keamanan Siber yang Mandiri, Tangguh, Presisi, dan Otonom"**. Platform ini dirancang bukan sekadar sebagai alat pemindai kode biasa, melainkan sebagai manifestasi tekad untuk melindungi ekosistem perangkat lunak di Indonesia dan dunia dari ancaman kerentanan siber melalui pendekatan analisis deterministik yang digabungkan dengan kecerdasan buatan terpadu.

### 🇬🇧 English
**KarsaSec** embodies **"The Noble Will & Unwavering Determination to Build a Sovereign, Resilient, Precise, and Autonomous Cybersecurity Fortress"**. This platform is engineered not merely as a conventional code scanner, but as a manifestation of a noble pledge to protect software ecosystems in Indonesia and worldwide from cyber threats through deterministic AST analysis combined with integrated AI security authority.

---

## ⚙️ Installation & Setup

You can install KarsaSec directly from the official GitHub repository:

```bash
# 1. Clone the repository
git clone https://github.com/aarsaputra/KarsaSec.git
cd KarsaSec

# 2. Install KarsaSec with core dependencies
pip install -e .

# Optional: Install development & testing dependencies
pip install -e '.[dev]'

# 3. Verify installation
karsasec doctor
```

## 📌 Overview

**KarsaSec** is a high-performance, production-grade static application security testing (SAST) platform. Built from the ground up to power modern DevSecOps pipelines, KarsaSec combines deterministic **Abstract Syntax Tree (AST) matching**, **Incremental Data-Flow & Taint Engine**, **Semantic Finding Qualification**, **Declarative Compatibility Registry**, **hybrid evidence scoring**, **SARIF standard reporting**, and a **Distributed AI Provider Gateway & Token-Budget Fencing Engine** with multi-language support (**Python, JavaScript/TypeScript, PHP, Go, Rust, Java**) and Infrastructure-as-Code (**Dockerfile, Kubernetes, GitHub Actions, Terraform, Helm**).

---

## ✨ Key Features & Capabilities

- **🤖 Distributed AI Provider Gateway (Sprint F10)**: Production-grade multi-provider AI Gateway featuring atomic token-budget fencing (`AIBudgetService`), state-machine request lifecycle (`AIRequestStateService`), deterministic cost-aware routing (`ProviderRouter`), and transactional outbox/audit ledger integration (`AIEventService`).
- **🚀 Dual-Engine AST & Token Matching**: High-throughput streaming AST traversal (`ASTWalker`) backed by Tree-sitter bindings and native parser fallbacks.
- **🛡️ Incremental Data-Flow & Taint Analysis**: Bounded interprocedural taint propagation engine verifying data flows (`$_GET`, `$_POST`, `os.Args`, etc.), tracing assignments, and constant resolution (`ConstantResolver`).
- **🎯 Semantic Finding Qualifier & FP Taxonomy**: Formal state-machine engine classifying candidates into `CONFIRMED`, `REJECTED`, or `UNRESOLVED` with explicit taxonomy reasons (`FPTaxonomyReason`). Zero silent drops.
- **⚡ Declarative Compatibility Registry**: Capability matrix checking source-to-sink and sanitizer-to-sink compatibility (e.g. `htmlspecialchars` vs `escapeshellarg`).
- **🧱 Language-Agnostic Generic IR**: Built-in Intermediate Representation (`karsasec/ir/`) decoupling security rules from language-specific AST structures.
- **⚡ Dedicated Runtime & Capability DAG Scheduler**: Autonomous DAG planner (`karsasec/runtime/`) for dynamic lazy analysis pass resolution (`AST -> SEMANTIC -> CALLGRAPH -> DATAFLOW`).
- **🎯 Intelligent Target Detector**: Auto-detects target kinds and formats via path heuristics and structural content inspection (`TargetDetector`).
- **🗂️ Persistent Symbol Store**: Enterprise project symbol database (`karsasec/index/`) for cross-file symbol indexing and instant reference lookup.
- **🔌 Extensible Plugin SDK**: Versioned Analysis API (`v1`, `v2`, `v3`) for third-party parser, rule pack, and reporter extensions (`karsasec/sdk/`).
- **📜 Rule Schema v2 Engine & Contract**: Advanced rule definitions featuring `TargetSpec`, `AnalysisSpec` (`requires: ["ast", "semantic"]`), `EvidenceSpec`, CWE/OWASP taxonomy mapping, and formal Rule Contracts (Detection, Safety, Fixtures, Regression).
- **📊 Hybrid Evidence & Confidence Engine**: Evaluates evidence telemetry dynamically to assign high-precision confidence levels (`CONFIDENT`, `HIGH`, `MEDIUM`, `LOW`).
- **🔍 Local Hybrid RAG Retrieval**: Use `karsasec scan --rag` or `karsasec scan --context-search` to attach contextual references from the local security corpus during scan.
- **🌐 Multi-Language & IaC Support**: Built-in AST and pattern detection for **Python**, **JavaScript / TypeScript**, **PHP**, **Go**, **Rust**, **Java**, **Dockerfile**, **Kubernetes**, **GitHub Actions**, **Terraform**, and **Helm**.
- **📄 Enterprise Reporting, Baseline & Qualification**: Generates **SARIF 2.1.0**, **JSON**, and interactive **Console** reports, with benchmark qualification reporting (`karsasec qualify --benchmark dvwa`).

---

## 📊 Supported Vulnerability Taxonomies (Rule Pack)

> [!NOTE]
> Below is a **representative sample** of supported rule patterns. KarsaSec includes **143+ deterministic YAML rules** spanning 6 programming languages and 5 Infrastructure-as-Code formats located in `karsasec/rules/patterns/`.

| Language / Format | Rule ID | Vulnerability | CWE | OWASP |
| :--- | :--- | :--- | :--- | :--- |
| **Python** | `KS-PY-0001` | SQL Injection (`sqlite3`, `psycopg2`) | CWE-89 | A03:2021-Injection |
| **Python** | `KS-PY-0002` | Command Injection (`subprocess`, `os`) | CWE-78 | A03:2021-Injection |
| **Python** | `KS-PY-0003` | Unsafe Deserialization (`pickle`, `yaml`) | CWE-502 | A08:2021-Software & Data Integrity |
| **JavaScript** | `KS-JS-0001` | Eval Code Injection (`eval`, `Function`) | CWE-95 | A03:2021-Injection |
| **JavaScript** | `KS-JS-0002` | DOM Cross-Site Scripting (`innerHTML`) | CWE-79 | A03:2021-Injection |
| **PHP** | `KS-PHP-0001` | Remote Code Execution (`eval`, `system`) | CWE-94 | A03:2021-Injection |
| **PHP** | `KS-PHP-0002` | SQL Injection (`mysqli`, `PDO`) | CWE-89 | A03:2021-Injection |
| **Go** | `KS-GO-0001` | SQL Injection (`db.Query`, `db.Exec`) | CWE-89 | A03:2021-Injection |
| **Go** | `KS-GO-0002` | Command Injection (`exec.Command`) | CWE-78 | A03:2021-Injection |
| **Rust** | `KS-RUST-0001` | Server-Side Request Forgery (`reqwest`, `ureq`) | CWE-918 | A10:2021-SSRF |
| **Java** | `KS-JAVA-0001` | Server-Side Request Forgery (`HttpURLConnection`, `HttpClient`) | CWE-918 | A10:2021-SSRF |
| **Dockerfile** | `KS-DOCKER-0001` | Root User Execution (`USER root`) | CWE-250 | A05:2021-Security Misconfig |
| **Kubernetes** | `KS-K8S-0001` | Privileged Container Execution (`privileged: true`) | CWE-250 | A05:2021-Security Misconfig |
| **GitHub Actions** | `KS-GHA-0001` | Unchecked Script Injection (`github.event`) | CWE-94 | A03:2021-Injection |
| **Common** | `KS-COMMON-0001` | Hardcoded Secrets & Credentials | CWE-798 | A07:2021-Identification & Auth |

---

## ⚡ CLI Usage & Command Reference

KarsaSec provides a powerful, intuitive CLI interface:

### 1. `karsasec scan [PATH]` — Fast Static Security Scan
Runs deterministic AST scanning and incremental dataflow analysis on the target directory.

```bash
# Basic workspace scan
karsasec scan .

# Scan with hybrid context retrieval from local security RAG corpus
karsasec scan . --rag

# Scan with specific RAG query context
karsasec scan . --rag --rag-query "server-side request forgery"

# Export report to SARIF 2.1.0 or JSON format
karsasec scan . -f sarif -o report.sarif.json
karsasec scan . -f json -o report.json
```

### 2. `karsasec review [PATH]` — Autonomous 4-Agent Security Audit
Runs a full multi-agent security audit pipeline (**Planner → Analyzer → Remediator → Reporter**).

```bash
karsasec review ./src
```

### 3. `karsasec patch` — AI Remediation & Visual Diff Review
Generates and applies proven secure patches with **GitHub-Style Visual Diff** previews (`-` red, `+` green) and **SAST Rescan Certification (Invariant L7)**.

```bash
# Preview remediation diff for a scan proposal
karsasec patch apply proposal.json

# Apply patch to an isolated Git branch (e.g. fix/karsasec-finding-KS-PHP-0001)
karsasec patch apply proposal.json --create-branch
```

### 4. `karsasec qualify` — Benchmark Qualification Verification
Verifies detector precision and false-positive rates against benchmark targets (e.g., DVWA).

```bash
karsasec qualify --benchmark dvwa
```

### 5. `karsasec rules` — Rule Registry Management
Inspects and validates rule packs.

```bash
# List all active rules
karsasec rules list

# Validate rule definitions syntax
karsasec rules validate
```

### 6. `karsasec doctor` & `karsasec init` — System Health & Configuration
Diagnoses environment readiness or generates `karsasec.yaml`.

```bash
# Run system diagnostic check
karsasec doctor

# Generate default configuration file
karsasec init
```


### Run Tests & Platform Verification

```bash
# Execute full test suite including AI Provider Gateway & Phase 5 adversarial verification
pytest -v
```

---

## ⚙️ How KarsaSec Engine Works

KarsaSec menganalisis berkas kode melalui tahapan eksekusi deterministik:

1. **📄 Multi-Language Ingestion & AST Parsing**: Setiap berkas proyek diidentifikasi oleh `ParserRegistry` dan diubah menjadi pohon AST menggunakan parser C-Tree-sitter atau parser fallback native.
2. **🔍 Deterministic Predicate Matching**: `ASTWalker` menelusuri simpul AST secara streaming. Pipeline predikat mencocokkan pola aturan secara cepat.
3. **📊 Evidence Collection & Hybrid Confidence Scoring**: `EvidenceCollector` mengekstrak cuplikan kode dan `ConfidenceCalculator` menghitung nilai keyakinan.
4. **🤖 Distributed AI Provider Gateway & Transactional Audit**: `AIBudgetService`, `AIRequestStateService`, `ProviderRouter`, dan `AIEventService` menangani permintaan AI secara transactional-safe, outbox-staged, dan budget-fenced.

---

## 📚 Documentation Directory

Detailed architectural & sprint audit documentation is organized in **[docs/](docs/README.md)**:

- 🟢 **[Master Documentation Hub & Index](docs/README.md)** — Complete master index of all PRDs, ADRs, and audit reports
- 🔒 **[Governing Roadmap Lock](FINAL_ROADMAP_LOCK.md)** — Formal governance lock for E9–E21 & Phase V0
- 🛡️ **[Sprint E21 Internal Readiness Review](docs/e21_internal_readiness_review.md)** — Final certification audit report
- 📊 **[Risk-Coverage Matrix](docs/RISK_COVERAGE_MATRIX.md)** — Failure mode to adversarial test mapping
- 🛡️ **[Phase V0 Validation Verdict Report](docs/v0_validation_report.md)** — Real-world vulnerability benchmark scorecard
- 🗺️ **[Implementation Roadmap](docs/IMPLEMENTATION_ROADMAP.md)** — Master execution strategy

---

## 🙏 Acknowledgments & Research Foundation

KarsaSec incorporates conceptual research, taxonomy patterns, and benchmark methodologies derived from pioneering open-source security analysis tools and research repositories:

- **[Semgrep](https://github.com/semgrep/semgrep)** — Structural AST pattern matching, rule syntax ergonomics, and interprocedural taint flow analysis concepts.
- **`sast-skills` & `sast-scan`** — Real-world vulnerability corpus patterns, static analysis benchmarks, and multi-language sink/source taxonomies.
- **`awesome-ai-security-tools` & `static-analysis`** — Open security research indexes and static code analysis paradigms.

We express our sincere gratitude to the global open-source security community, researchers, and maintainers whose work provided invaluable foundation benchmarks and conceptual inspiration for KarsaSec.

---

## 🛡️ License

Distributed under the **[Apache 2.0 License](LICENSE)**.
