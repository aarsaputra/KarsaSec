# KarsaSec User Guide & Documentation Navigation

Welcome to the **KarsaSec User Guide**. This document explains how to use the KarsaSec CLI commands, navigate the `docs/` directory, and utilize the AI Remediation and scanning capabilities.

---

## 🧭 Navigating the `docs/` Directory

The `docs/` directory is structured to provide clear documentation for users, security engineers, and developers:

```text
docs/
├── README.md                          # Master Documentation Hub & System Index
├── guides/
│   └── user_guide.md                 # This User Guide (CLI & Workflow usage)
├── specs/                             # Architecture specifications & PRDs (E9-E20)
├── audit_history/                     # Independent verification & certification logs
├── RISK_COVERAGE_MATRIX.md            # Failure mode & test coverage matrix
├── RULE_COVERAGE_MATRIX.md            # Vulnerability taxonomy & rule mapping
└── IMPLEMENTATION_ROADMAP.md          # Project roadmap and sprint specs
```

---

## 💻 Complete CLI Command Reference

### 1. `karsasec scan` — Deterministic SAST Scan
Performs high-speed AST pattern matching and bounded dataflow analysis.

**Syntax**: `karsasec scan [TARGET_PATH] [OPTIONS]`

**Key Options**:
- `--format, -f [console|json|sarif]`: Output format (Default: `console`).
- `--output, -o [FILE_PATH]`: Write report output to a file.
- `--baseline, -b [BASELINE_FILE]`: Compare findings against a baseline JSON.
- `--rag`: Enable local RAG security context retrieval during scanning.
- `--rag-query [QUERY]`: Provide custom query context for RAG retrieval.

**Examples**:
```bash
# Basic scan of current directory
karsasec scan .

# Scan with SARIF report export for GitHub Security tab
karsasec scan ./src -f sarif -o results.sarif.json

# Scan with RAG context search for SQL Injection rules
karsasec scan . --rag --rag-query "SQL Injection sanitization"
```

---

### 2. `karsasec review` — Autonomous 4-Agent Review
Executes the full 4-agent security audit workflow (**Planner → Analyzer → Remediator → Reporter**).

**Syntax**: `karsasec review [TARGET_PATH]`

**Example**:
```bash
karsasec review ./web_app
```

---

### 3. `karsasec patch` — AI Patch Suggestion & GitHub-Style Diff
Applies AI or template-generated secure patches with **GitHub-Style Visual Diff** previews (`-` red, `+` green) and **SAST Rescan Certification**.

**Syntax**: `karsasec patch apply [PROPOSAL_JSON] [OPTIONS]`

**Key Options**:
- `--interactive / --no-interactive`: Prompt for user approval before modifying files.
- `--create-branch`: Automatically checkout an isolated Git branch (`fix/karsasec-finding-<id>`) before applying.

**Examples**:
```bash
# Preview patch diff and apply interactively
karsasec patch apply proposal.json

# Apply patch to an isolated Git branch
karsasec patch apply proposal.json --create-branch
```

---

### 4. `karsasec qualify` — Benchmark Qualification
Runs SAST precision qualification against standard benchmark applications (e.g. DVWA).

**Example**:
```bash
karsasec qualify --benchmark dvwa
```

---

### 5. `karsasec rules` — Rule Pack Management
Inspects registered rules and validates custom YAML rule definitions.

**Examples**:
```bash
# List all active rules (143+ rules across Python, PHP, JS, Go, Rust, Java, IaC)
karsasec rules list

# Validate YAML rule syntax
karsasec rules validate
```

---

### 6. `karsasec doctor` & `karsasec init` — Environment Health & Config
Diagnoses setup issues or creates `karsasec.yaml`.

```bash
# Check Python version, cache health, and LLM configuration
karsasec doctor

# Create default configuration file
karsasec init
```

---

## 🤖 Configuring AI & LLM Settings

KarsaSec allows you to configure whether and how AI/LLM models are integrated into your security scanning and remediation workflow.

### 1. Opting In/Out of AI (RAG Context)
By default, standard scans do not use AI retrieval. To enable local hybrid RAG (Retrieval-Augmented Generation) context lookup:
* **Enable RAG**: Add the `--rag` flag to the scan command:
  ```bash
  karsasec scan . --rag
  ```
* **Disable RAG / Standalone Mode**: Simply run scans without the `--rag` flag to use pure deterministic AST and data-flow analysis (recommended for air-gapped CI/CD environments).

### 2. Configuring LLM Provider and Models
You can configure the default AI model and token fencing either via environment variables or the `karsasec.yaml` configuration file.

#### Option A: via `karsasec.yaml`
Generate the configuration file using `karsasec init` and set the fields in the root of the file:
```yaml
# karsasec.yaml
default_llm_provider: "litellm"      # AI provider adapter (e.g., litellm, ollama)
default_llm_model: "gemini-2.5-flash" # Model identifier
max_token_budget_per_scan: 50000      # Max token limit per audit session to control costs
```

#### Option B: via `.env` or Environment Variables
Set the following environment variables in your shell or `.env` file:
```bash
KARSASEC_DEFAULT_LLM_PROVIDER=litellm
KARSASEC_DEFAULT_LLM_MODEL=gemini-2.5-flash
KARSASEC_MAX_TOKEN_BUDGET_PER_SCAN=50000
```

