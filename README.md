<p align="center">
  <img src="img/KarsaSec.webp" alt="KarsaSec Banner" width="100%">
</p>

<h1 align="center">🛡️ KarsaSec</h1>

<p align="center">
  <strong>Next-Generation Multi-Language AST Security Analysis Engine & Autonomous SecOS</strong>
</p>

<p align="center">
  <a href="https://github.com/aarsaputra/KarsaSec"><img src="https://img.shields.io/badge/Status-Sprint%20F10%20Completed-brightgreen?style=for-the-badge" alt="Status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python"></a>
  <a href="docs/IMPLEMENTATION_ROADMAP.md"><img src="https://img.shields.io/badge/Rules-Schema%20v2-orange?style=for-the-badge" alt="Schema v2"></a>
</p>

---

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

## ⚡ Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/aarsaputra/KarsaSec.git
cd KarsaSec

# Install in editable mode
pip install -e .
```

### Usage

```bash
# Scan a project workspace
karsasec scan .

# Run a scan with hybrid context retrieval from local RAG corpus
karsasec scan . --rag
karsasec scan . --rag --rag-query "server-side request forgery"

# Export scan results to SARIF or JSON
karsasec scan . -f sarif -o report.sarif.json
karsasec scan . -f json -o report.json

# System & diagnostic check
karsasec doctor

# Check version
karsasec --version
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

Detailed architectural & sprint audit documentation is organized in `docs/`:

- 🛡️ **[Sprint F10 Final Adversarial Audit Report](docs/f10_final_adversarial_audit.md)** — Forensic crash boundary matrix & F9 immutability audit report
- 📤 **[Sprint F10 Transactional Audit & Outbox](docs/f10_phase4_transactional_audit.md)** — Transactional outbox & audit ledger integration specification
- 🔀 **[Sprint F10 Cost-Aware Provider Router](docs/f10_phase3_provider_router.md)** — Multi-provider routing policy & health failover
- 💰 **[Sprint F10 Budget Fencing & State Machine](docs/f10_phase2_budget_fencing.md)** — Token-budget reservation & request state machine
- 🗄️ **[Sprint F10 Database Schema](docs/f10_database_schema.md)** — PostgreSQL/SQLAlchemy ORM specifications
- 🏗️ **[Sprint F10 Architecture Audit](docs/f10_architecture_audit.md)** — Distributed AI Gateway architecture audit
- 🛡️ **[Sprint F9 Security Baseline Audit](docs/f9_final_adversarial_audit.md)** — Disaster recovery & snapshot replay audit
- 🗺️ **[Implementation Roadmap](docs/IMPLEMENTATION_ROADMAP.md)** — Master execution strategy

---

## 🛡️ License

Distributed under the **[Apache 2.0 License](LICENSE)**.
