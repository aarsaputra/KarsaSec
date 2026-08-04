<p align="center">
  <img src="img/KarsaSec.png" alt="KarsaSec Banner" width="100%">
</p>

<h1 align="center">🛡️ KarsaSec</h1>

<p align="center">
  <strong>Next-Generation Multi-Language AST Security Analysis Engine & Autonomous SecOS</strong>
</p>

<p align="center">
  <a href="https://github.com/aarsaputra/KarsaSec"><img src="https://img.shields.io/badge/Status-Sprint%203C%20Completed-brightgreen?style=for-the-badge" alt="Status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python" alt="Python"></a>
  <a href="docs/IMPLEMENTATION_ROADMAP.md"><img src="https://img.shields.io/badge/Rules-Schema%20v2-orange?style=for-the-badge" alt="Schema v2"></a>
</p>

---

## 📌 Overview

**KarsaSec** is a high-performance, production-grade static application security testing (SAST) platform. Built from the ground up to power modern DevSecOps pipelines, KarsaSec combines deterministic **Abstract Syntax Tree (AST) matching**, **Schema v2 security rules**, **hybrid evidence scoring**, and **SARIF standard reporting** with multi-language support (**Python, JavaScript/TypeScript, PHP, Go**).

---

## ✨ Key Features & Capabilities

- **🚀 Dual-Engine AST & Token Matching**: High-throughput streaming AST traversal (`ASTWalker`) backed by Tree-sitter bindings and native parser fallbacks.
- **📜 Rule Schema v2 Engine**: Advanced rule definitions featuring `TargetSpec`, `AnalysisSpec` (AST, Pattern, CPG), `EvidenceSpec`, and CWE/OWASP taxonomy mapping with 100% Schema v1 backward compatibility.
- **📊 Hybrid Evidence & Confidence Engine**: Evaluates evidence telemetry (sinks, sources, hardcoded strings) dynamically to assign high-precision confidence levels (`CONFIDENT`, `HIGH`, `MEDIUM`, `LOW`).
- **🛡️ Standardized Security Corpus**: Includes positive control (`vulnerable/`), negative control (`safe/`), and `regression/` suites per vulnerability pattern to guarantee **zero false positives**.
- **🌐 Multi-Language Support**: Built-in AST and pattern detection for **Python**, **JavaScript / TypeScript**, **PHP**, **Go**, and **Common Credentials/Secrets**.
- **📄 Enterprise Reporting & Baseline**: Generates **SARIF 2.1.0**, **JSON**, and interactive **Console** reports, with baseline differential scanning to track `NEW`, `EXISTING`, `FIXED`, and `REGRESSED` findings.

---

## 📊 Supported Vulnerability Taxonomies (Rule Pack)

| Language | Rule ID | Vulnerability | CWE | OWASP |
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

# Run a deep security review
karsasec review .

# System & diagnostic check
karsasec doctor

# Check version
karsasec --version
```

### Run Tests & Security Corpus Validation

```bash
# Execute unit test suite & security corpus verification (70/70 passing)
python3 -m pytest tests/ -v
```

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

---

## 🛡️ License

Distributed under the **[Apache 2.0 License](LICENSE)**.
