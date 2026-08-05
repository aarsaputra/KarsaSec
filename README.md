<p align="center">
  <img src="img/KarsaSec.webp" alt="KarsaSec Banner" width="100%">
</p>

<h1 align="center">🛡️ KarsaSec</h1>

<p align="center">
  <strong>Next-Generation Multi-Language AST Security Analysis Engine & Autonomous SecOS</strong>
</p>

<p align="center">
  <a href="https://github.com/aarsaputra/KarsaSec"><img src="https://img.shields.io/badge/Status-Sprint%209.7%20Completed-brightgreen?style=for-the-badge" alt="Status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python"></a>
  <a href="docs/IMPLEMENTATION_ROADMAP.md"><img src="https://img.shields.io/badge/Rules-Schema%20v2-orange?style=for-the-badge" alt="Schema v2"></a>
</p>

---

## 📌 Overview

**KarsaSec** is a high-performance, production-grade static application security testing (SAST) platform. Built from the ground up to power modern DevSecOps pipelines, KarsaSec combines deterministic **Abstract Syntax Tree (AST) matching**, **Schema v2 security rules**, **hybrid evidence scoring**, and **SARIF standard reporting** with multi-language support (**Python, JavaScript/TypeScript, PHP, Go, Rust, Java**) and Infrastructure-as-Code (**Dockerfile, Kubernetes, GitHub Actions, Terraform, Helm**).

---

## ✨ Key Features & Capabilities

- **🚀 Dual-Engine AST & Token Matching**: High-throughput streaming AST traversal (`ASTWalker`) backed by Tree-sitter bindings and native parser fallbacks.
- **🛡️ Taint Analysis & Guard Verification**: Eliminates SAST false positives by verifying untrusted data flows (`$_GET`, `$_POST`, etc.), filtering out hardcoded static sinks, and checking switch-case whitelist guards.
- **🧱 Language-Agnostic Generic IR**: Built-in Intermediate Representation (`karsasec/ir/`) decoupling security rules from language-specific AST structures.
- **⚡ Dedicated Runtime & Capability DAG Scheduler**: Autonomous DAG planner (`karsasec/runtime/`) for dynamic lazy analysis pass resolution (`AST -> SEMANTIC -> CALLGRAPH -> DATAFLOW`).
- **🎯 Intelligent Target Detector**: Auto-detects target kinds and formats via path heuristics and structural content inspection (`TargetDetector`).
- **🗂️ Persistent Symbol Store**: Enterprise project symbol database (`karsasec/index/`) for cross-file symbol indexing and instant reference lookup.
- **🔌 Extensible Plugin SDK**: Versioned Analysis API (`v1`, `v2`, `v3`) for third-party parser, rule pack, and reporter extensions (`karsasec/sdk/`).
- **📜 Rule Schema v2 Engine**: Advanced rule definitions featuring `TargetSpec`, `AnalysisSpec` (`requires: ["ast", "semantic"]`), `EvidenceSpec`, and CWE/OWASP taxonomy mapping.
- **📊 Hybrid Evidence & Confidence Engine**: Evaluates evidence telemetry dynamically to assign high-precision confidence levels (`CONFIDENT`, `HIGH`, `MEDIUM`, `LOW`).
- **🔍 Local Hybrid RAG Retrieval**: Use `karsasec scan --rag` or `karsasec scan --context-search` to attach contextual references from the local security corpus during scan.
- **🌐 Multi-Language & IaC Support**: Built-in AST and pattern detection for **Python**, **JavaScript / TypeScript**, **PHP**, **Go**, **Rust**, **Java**, **Dockerfile**, **Kubernetes**, **GitHub Actions**, **Terraform**, and **Helm**.
- **📄 Enterprise Reporting & Baseline**: Generates **SARIF 2.1.0**, **JSON**, and interactive **Console** reports, with deterministic 32-character SHA-256 fingerprinting (`compute_stable_finding_fingerprint`).

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

# Use a custom external corpus directory, for example a public repo checkout or downloaded security corpus
# Example: clone a public security corpus repository then pass its path to --rag-corpus
# git clone https://github.com/OWASP/CheatSheetSeries.git /tmp/owasp-corpus
karsasec scan . --rag --rag-corpus /tmp/owasp-corpus

Note: Sprint 5 — Hybrid RAG integration is complete. Retrieved RAG context is now available to the analysis engine via `VisitorContext.rag_context`, and rules can opt-in to RAG-aware predicates (see `karsasec.rules.matcher.predicates.rag.RAGPredicate`).

# Export scan results to SARIF or JSON
karsasec scan . -f sarif -o report.sarif.json
karsasec scan . -f json -o report.json

# Run a deep security review
karsasec review .

# System & diagnostic check
karsasec doctor

# Check version
karsasec --version
```

### Run Tests & Platform Verification

```bash
# Execute unit test suite & platform verification (137/137 passing)
python3 -m pytest tests/ -v
```

---

## ⚙️ How KarsaSec Engine Works (Cara Kerja Engine)

KarsaSec menganalisis berkas kode melalui 4 tahapan eksekusi deterministik:

1. **📄 Multi-Language Ingestion & AST Parsing**:
   Setiap berkas proyek diidentifikasi oleh `ParserRegistry` dan diubah menjadi pohon AST (`FileNode` & `ASTNode`) menggunakan parser C-Tree-sitter atau parser fallback native.

2. **🔍 Deterministic Predicate Matching**:
   `ASTWalker` menelusuri simpul AST secara streaming. Pipeline predikat (`NodeTypePredicate`, `SymbolPredicate` dengan regex word boundary `\b`, `RegexPredicate`, `LiteralPredicate`) mencocokkan pola aturan secara cepat (*short-circuiting*).

3. **📊 Evidence Collection & Hybrid Confidence Scoring**:
   `EvidenceCollector` mengekstrak cuplikan kode dan konteks baris. `ConfidenceCalculator` menghitung nilai keyakinan berbasis akumulasi pembobotan bukti kerentanan (*sink*, *source*, *hardcoded string*).

4. **📄 Fingerprinting, Baseline & Standard Reporting**:
   Setiap temuan diberi sidik jari SHA-256 unik oleh `FindingFactory` untuk mencegah duplikasi. Mesin pembanding baseline memisahkan temuan menjadi `NEW`, `EXISTING`, `FIXED`, atau `REGRESSED` dan mengekspornya ke format **SARIF 2.1.0**, **JSON**, atau **Console CLI**.

---

## 🏗️ Core Architecture

```
                                  Source Code / File Stream
                                              │
                                              ▼
                                   ┌──────────────────────┐
                                   │    Parser Registry   │
                                   └──────────┬───────────┘
                                              │
                       ┌──────────────────────┼──────────────────────┐
                       ▼                      ▼                      ▼
             ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
             │  Python Parser   │   │ Generic TS Engine│   │ Tokenizer Engine │
             └─────────┬────────┘   └─────────┬────────┘   └─────────┬────────┘
                       └──────────────────────┼──────────────────────┘
                                              │
                                              ▼
                                   ┌──────────────────────┐
                                   │  FileNode / ASTNode  │
                                   └──────────┬───────────┘
                                              │
                                              ▼
                                   ┌──────────────────────┐
                                   │  Predicate Pipeline  │
                                   │ (NodeType, Symbol,   │
                                   │  Regex, Literal)     │
                                   └──────────┬───────────┘
                                              │
                                              ▼
                                   ┌──────────────────────┐
                                   │  Evidence & Scoring  │
                                   │ ConfidenceCalculator │
                                   └──────────┬───────────┘
                                              │
                                              ▼
                                   ┌──────────────────────┐
                                   │ Finding & Reporters  │
                                   │ (SARIF, JSON, CLI)   │
                                   └──────────┬───────────┘
                                              │
                                              ▼
                                   ┌──────────────────────┐
                                   │ Differential Baseline│
                                   │ (.karsasec-baseline) │
                                   └──────────────────────┘
```

---

## 📚 Documentation Directory

Detailed architectural documentation is organized in `docs/`:

- 🗺️ **[Implementation Roadmap](docs/IMPLEMENTATION_ROADMAP.md)** — Master 9-Sprint execution strategy
- 📐 **[Project Blueprint](docs/blueprint/PROJECT_BLUEPRINT.md)** — Vision of SecOS & platform paradigm
- 🤖 **[Agent Specifications](docs/architecture/AGENT_SPECIFICATIONS.md)** — Agent topology & DAG specifications
- 🔬 **[Research Foundation](docs/research/RESEARCH_FOUNDATION.md)** — Theoretical & academic security research
- 💻 **[Development Guide](docs/guides/DEVELOPMENT.md)** — Developer setup & environment guide
- 🤝 **[Contributing Guide](docs/guides/CONTRIBUTING.md)** — Contribution workflow & guidelines
- 🧪 **[Testing Strategy](docs/guides/TESTING.md)** — Automated testing strategy & corpus specifications

## Recent Additions

- Added OWASP Top-10 rule coverage expansion for Python, JavaScript, Go, Rust, and Java.
- New rules: `KS-PY-0004`, `KS-PY-0010`, `KS-JS-0006`, `KS-GO-0008` with accompanying security_corpus samples and unit tests.
- Continuous validation CI workflow: `.github/workflows/corpus-validation.yml` runs corpus validation and multi-language rule tests on PRs.

If you want these added to project documentation pages, I can generate a short changelog fragment or PR-ready summary.

---

## 🛡️ License

Distributed under the **[Apache 2.0 License](LICENSE)**.
