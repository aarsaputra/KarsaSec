# 🛡️ KarsaSec — Agent Specifications v2.5 (Canonical)

**Platform:** KarsaSec AI Application Security Operating System  
**Arsitektur:** Event-Driven Workflow Engine + DAG Orchestration  
**Total Agen:** 13 Core Agents (AG-00 s/d AG-12)  
**Versi Dokumen:** 2.5 | **Terakhir Diperbarui:** 2026-08-04

> Dokumen ini adalah **satu-satunya spesifikasi agen canonical** untuk KarsaSec.  
> Semua versi sebelumnya (v1.0 / 9 agen, v2.0 / 12 agen) telah digantikan oleh v2.5 ini.

---

KarsaSec diarsitekturkan sebagai **Event-Driven Workflow Execution Engine** berbasis DAG (Directed Acyclic Graph), verifikasi berulang (*Iterative Reflection Loop*), dan integrasi alat analisis keamanan terisolasi.

---## 1. Platform Architecture & Event-Driven Topology

Setiap permintaan pemindaian keamanan diproses melalui **Event Bus** secara asinkron. DAG Planner menerbitkan alur kerja, Agent Workers mengambil tasks dari antrean dan mengeksekusi secara paralel, lalu mengirimkan status ke Memory Store.
flowchart TD
    A[Trigger: CI/CD / PR / CLI / Webhook] --> EB[Event Bus / Message Queue]
    
    subgraph Discovery & Workflow Planning
        EB --> AG00[AG-00: Project Discovery Agent]
        AG00 -- Project Profile --> AG01[AG-01: Workflow DAG Planner & Cost Router]
        AG01 -- Generates Workflow DAG --> MB[(Memory & Learning Cache Store)]
    end

    subgraph Context Building & Indexing
        AG01 --> AG02[AG-02: Project Indexer Agent]
        AG02 --> AG03[AG-03: Code Property Graph Builder]
        AG01 --> AG04[AG-04: Knowledge & RAG Specialist]
    end

    subgraph Specialist Analysis Execution Engine (Parallel Async Workers)
        AG03 & AG04 --> AG05[AG-05: Threat Model Architect]
        AG03 & AG04 --> AG06[AG-06: Secure Code Reviewer - SAST]
        AG03 & AG04 --> AG07[AG-07: Supply Chain Security Agent]
        AG03 & AG04 --> AG08[AG-08: DevSecOps & Runtime Security Auditor]
    end

    subgraph Remediation & Iterative Validation Loop
        AG06 & AG07 & AG08 --> AG09[AG-09: Patch & Remediation Specialist]
        AG05 & AG06 & AG07 & AG08 & AG09 --> AG10[AG-10: Policy & Enterprise Governance Engine]
        AG10 --> AG11[AG-11: Reflection & Anti-Hallucination Validator]
        
        %% Iterative Loop
        AG11 -- Patch Rejected / Breaking Changes Detected --> AG09
        AG11 -- False Positive Identified / Revision Needed --> AG01
    end

    subgraph Output Generation & Memory Sync
        AG11 -- Approved Findings & Validated Diffs --> AG12[AG-12: Security Report & Artifact Writer]
        AG12 --> Out[SARIF / PR Comments / Executive Dashboard]
        AG12 -- Update Learning Cache & Accepted Risks --> MB
    end
## 2. Iterative Reflection & Re-Patch Loop

KarsaSec tidak menggunakan single-pass validation. Jika **AG-11** menemukan patch dari **AG-09** menimbulkan *breaking changes* atau merusak AST, sistem otomatis memicu **Re-Patch Loop** hingga perbaikan dinyatakan aman.
sequenceDiagram
    autonumber
    participant Specialist as AG-06 / AG-07 (Specialist)
    participant Patch as AG-09 (Patch Specialist)
    participant Policy as AG-10 (Policy Engine)
    participant Validator as AG-11 (Reflection & Validator)
    participant Memory as Memory & Learning Cache

    Specialist->>Patch: Kirim Kerentanan Terverifikasi (Source-to-Sink)
    Patch->>Patch: Buat Patch (Unified Diff) & Cek Gaya Penulisan Proyek
    Patch->>Policy: Kirim Patch + Findings
    Policy->>Validator: Evaluasi Aturan Bisnis & Kebijakan Enterprise
    
    rect rgb(240, 248, 255)
        note over Validator: Iterative Reflection Check
        Validator->>Validator: Simulasikan Sintaks AST & Verifikasi Sanitasi
        alt Patch Merusak AST / False Positive
            Validator-->>Patch: Minta Revisi Patch (Iterative Re-patch)
        else Patch Lolos Verifikasi
            Validator->>Memory: Simpan Fix yang Berhasil ke Learning Cache
            Validator->>Report: Loloskan ke AG-12 (Report Writer)
        end
    end
## 3. LiteLLM Abstraction & Cost Controller Matrix

KarsaSec membagi kapabilitas model ke dalam **3 Tier**. AG-01 mengalokasikan token budget per simpul DAG. Konfigurasi model konkret dikelola di `config/provider_routes.yaml`.
                            ┌───────────────────────────────────┐
                            │    LiteLLM Unified Interface     │
                            └─────────────────┬─────────────────┘
                                              │
         ┌────────────────────────────────────┼────────────────────────────────────┐
         │                                    │                                    │
┌────────┴────────┐                  ┌────────┴────────┐                  ┌────────┴────────┐
│   Tier 1: Fast  │                  │ Tier 2: Balanced│                  │ Tier 3: Complex │
│ (Low Latency)   │                  │ (High Precision)│                  │ (Deep Reasoning)│
│ e.g. Gemini 2.5 │                  │ e.g. Claude 3.5 │                  │ e.g. Claude 3.5 │
│ Flash, GPT-4o-  │                  │ Sonnet, GPT-4o  │                  │ Opus, o3-mini   │
│ mini, DeepSeek  │                  │                 │                  │                 │
└────────┬────────┘                  └────────┬────────┘                  └────────┬────────┘
         │                                    │                                    │
   AG-00, AG-02,                        AG-01, AG-04,                        AG-05, AG-09,
   AG-07, AG-12                        AG-03, AG-06,                        AG-11
                                       AG-08, AG-10
### Tabel Alokasi Model & Token Budget per Agen

| Agent ID | Nama Agen | LLM Tier | Tier Kapabilitas | Max Tokens | Timeout |
|---|---|---|---|---|---|
| AG-00 | Project Discovery | Tier 1 | Fast | 2,000 | 10s |
| AG-01 | Workflow DAG Planner | Tier 2 | Balanced | 4,000 | 15s |
| AG-02 | Project Indexer | Tier 1 | Fast | 6,000 | 15s |
| AG-03 | Code Property Graph | Tier 2 | Balanced | 12,000 | 30s |
| AG-04 | Knowledge & RAG | Tier 2 | Balanced | 4,000 | 15s |
| AG-05 | Threat Model Architect | Tier 3 | Complex | 12,000 | 45s |
| AG-06 | Secure Code Reviewer | Tier 2 | Balanced | 16,000 | 60s |
| AG-07 | Supply Chain Security | Tier 1 | Fast | 6,000 | 20s |
| AG-08 | DevSecOps & Runtime | Tier 2 | Balanced | 8,000 | 30s |
| AG-09 | Patch & Remediation | Tier 3 | Complex | 12,000 | 45s |
| AG-10 | Policy Engine | Tier 2 | Balanced | 4,000 | 15s |
| AG-11 | Reflection & Validator | Tier 3 | Complex | 16,000 | 60s |
| AG-12 | Security Report Writer | Tier 1 | Fast | 8,000 | 20s |

> **Catatan:** Model konkret per tier dikonfigurasi di `config/provider_routes.yaml`. Tabel di atas menunjukkan kapabilitas tier, bukan model yang di-*pin*.

## 4. Tool Registry Taxonomy & Schema

Setiap alat keamanan eksternal terdaftar formal dengan `tool_type`, level isolasi sandbox, dan versi terpasang.
tools:
  - id: "tool-semgrep-sast"
    name: "Semgrep Open-Source Static Analysis"
    tool_type: "SAST"
    version: "1.68.0"
    sandbox: "Isolated Process / Container"
    capabilities:
      - "ast_parsing"
      - "taint_tracking"
      - "pattern_matching"
    permissions:
      read_filesystem: true
      write_filesystem: false
      network_access: false
    command_template: "semgrep scan --config auto --json {input_path}"

  - id: "tool-trivy-sca"
    name: "Trivy Vulnerability & Misconfig Scanner"
    tool_type: "SCA"
    version: "0.50.1"
    sandbox: "Docker Container"
    capabilities:
      - "lockfile_audit"
      - "sbom_generation"
      - "iac_misconfig"
    permissions:
      read_filesystem: true
      write_filesystem: true
      network_access: true
    command_template: "trivy fs --format json --output {output_path} {input_path}"

  - id: "tool-ast-parser"
    name: "Tree-Sitter Unified AST Engine"
    tool_type: "FORMATTER"
    version: "0.22.2"
    sandbox: "In-Memory Native Binding"
    capabilities:
      - "call_graph_construction"
      - "symbol_resolution"
      - "syntax_validation"
    permissions:
      read_filesystem: true
      write_filesystem: false
      network_access: false

  - id: "tool-osv-api"
    name: "Open Source Vulnerability API"
    tool_type: "SCA"
    version: "v1"
    sandbox: "HTTP REST API"
    capabilities:
      - "cve_lookup"
      - "ghsa_lookup"
      - "malicious_package_check"
    permissions:
      read_filesystem: false
      write_filesystem: false
      network_access: true
## 5. Spesifikasi 13 Core Agents (AG-00 s/d AG-12)

### 5.1 AG-00: Project Discovery Agent
**Kategori:** Project Identification Layer  
**Peran:** Mendeteksi bahasa, framework, build system, package manager, monorepo, dan CI/CD secara deterministik.
id: AG-00
name: Project Discovery Agent
version: 2.5.0
category: Discovery
risk_level: Low
llm_tier: Tier 1 (Fast)
confidence_threshold: 0.95

mission: >
  Mengekstrak profil teknis proyek dari repositori secara akurat guna menjadi dasar acuan bagi Workflow DAG Planner.

inputs:
  - name: repository_root
    type: file_tree
    required: true

outputs:
  - name: project_profile
    format: json

allowed_tools:
  - tool-ast-parser

execution_rules:
  - Dilarang menebak framework jika file kunci (seperti composer.json, package.json, go.mod) tidak ditemukan.
  - Wajib memetakan struktur monorepo hingga ke batas sub-proyek (sub-packages).

anti_hallucination_checks:
  - Verifikasi bahwa setiap framework yang terdeteksi memiliki berkas manifestasi nyata di direktori.

### 5.2 AG-01: Workflow DAG Planner & Cost Router
**Kategori:** Orchestration Engine  
**Peran:** Menerima `project_profile` dari AG-00, menyusun DAG workflow, alokasi token budget, dan rute model LLM.
id: AG-01
name: Workflow DAG Planner & Cost Router
version: 2.5.0
category: Orchestrator
risk_level: High
llm_tier: Tier 2 (Balanced)
confidence_threshold: 0.90

mission: >
  Menyusun skenario eksekusi agen paralel berbasis DAG dan mengalokasikan anggaran biaya LLM
  berdasarkan tingkat kompleksitas analisis proyek.

inputs:
  - name: project_profile
    type: json
    required: true
  - name: user_intent
    type: string
    required: true

outputs:
  - name: execution_dag
    format: json

allowed_tools: []

execution_rules:
  - Kelompokkan agen spesialis (AG-05, AG-06, AG-07, AG-08) agar dapat berjalan secara paralel dalam DAG.
  - Selalu sertakan AG-10 (Policy Engine) dan AG-11 (Reflection Validator) sebelum pembuatan laporan akhir.

anti_hallucination_checks:
  - Pastikan agen yang dijadwalkan relevan dengan stack yang terdeteksi oleh AG-00.

### 5.3 AG-02: Project Indexer Agent
**Kategori:** Repository Structuring  
**Peran:** Mengklasifikasi direktori, membuat indeks simbol global, mengelompokkan berkas (Controller, Model, Service, Config, Test).
id: AG-02
name: Project Indexer Agent
version: 2.5.0
category: Indexing
risk_level: Low
llm_tier: Tier 1 (Fast)
confidence_threshold: 0.92

mission: >
  Membuat taksonomi dan indeks direktori proyek secara terstruktur guna mempermudah pembentukan Code Property Graph.

inputs:
  - name: repository_root
    type: file_tree
    required: true

outputs:
  - name: project_index
    format: json

allowed_tools:
  - tool-ast-parser

execution_rules:
  - Kelompokkan file berdasarkan kategori arsitektural (misal: entrypoints, business_logic, data_access).
  - Ekstrak seluruh file konfigurasi lingkungan (seperti `.env.example`, `config/*.yaml`).

anti_hallucination_checks:
  - Pastikan setiap jalur berkas dalam indeks benar-benar wujud pada struktur direktori asli.

### 5.4 AG-03: Code Property Graph Builder
**Kategori:** Code Graph Construction  
**Peran:** Membangun AST, Call Graph, Route-to-Controller Mapping, dan alur Data Flow Source-to-Sink.
id: AG-03
name: Code Property Graph Builder
version: 2.5.0
category: Context Provider
risk_level: Medium
llm_tier: Tier 2 (Balanced)
confidence_threshold: 0.90

mission: >
  Membangun representasi grafis struktural dari basis kode (Code Property Graph) untuk memberi konteks
  analisis mendalam bagi agen spesialis SAST dan Threat Model.

inputs:
  - name: source_files
    type: code_files
    required: true
  - name: project_index
    type: json
    required: true

outputs:
  - name: code_property_graph
    format: json

allowed_tools:
  - tool-ast-parser

execution_rules:
  - Petakan seluruh titik masuk (*Entry Points*) seperti HTTP Endpoints, CLI Commands, dan Event Handlers.
  - Identifikasi variabel input yang tidak terpercaya (*Uncontrolled User Inputs*).

anti_hallucination_checks:
  - Pastikan setiap simpul (*node*) pada Call Graph memiliki lokasi file dan nomor baris nyata.

### 5.5 AG-04: Knowledge Analyst & RAG Specialist
**Kategori:** Grounding & Knowledge Retrieval  
**Peran:** Pencarian vektor dan reranking terhadap CWE, CVE/GHSA, OWASP, dan standar internal.
id: AG-04
name: Knowledge Analyst & RAG Specialist
version: 2.5.0
category: Context Provider
risk_level: Medium
llm_tier: Tier 2 (Balanced)
confidence_threshold: 0.88

mission: >
  Menyediakan referensi standar keamanan, kutipan regulasi, dan basis data kerentanan terverifikasi (CVE/GHSA).

inputs:
  - name: query_keywords
    type: string
    required: true

outputs:
  - name: grounded_knowledge
    format: json

allowed_tools:
  - tool-osv-api

execution_rules:
  - Wajib menyertakan URL/Source ID terverifikasi untuk setiap kutipan standar.
  - Jika relevansi RAG < 0.75, tandai informasi sebagai "General Recommendation".

anti_hallucination_checks:
  - Dilarang merekayasa nomor CVE atau CWE fiktif. Always validate against API/Database eksternal.

### 5.6 AG-05: Threat Model & Security Architect
**Kategori:** Architectural Security Analysis  
**Peran:** Menganalisis alur data, Trust Boundaries, dan arsitektur Zero Trust berbasis STRIDE/PASTA.
id: AG-05
name: Threat Model & Security Architect
version: 2.5.0
category: Specialist Analysis
risk_level: Critical
llm_tier: Tier 3 (Complex)
confidence_threshold: 0.85

mission: >
  Mengidentifikasi kelemahan desain sistem, potensi kebocoran antar batas kepercayaan (Trust Boundaries),
  dan menyusun strategi pertahanan mendalam (Defense-in-Depth).

inputs:
  - name: code_property_graph
    type: json
    required: true
  - name: architecture_docs
    type: string # PlantUML, Mermaid, OpenAPI Spec, Architecture Docs
    required: false

outputs:
  - name: threat_model_findings
    format: json

allowed_tools: []

execution_rules:
  - Evaluasi alur otentikasi, otorisasi, enkripsi data, dan interaksi API eksternal.
  - Manfaatkan diagram PlantUML/Mermaid dan skema OpenAPI jika tersedia.

anti_hallucination_checks:
  - Pastikan setiap komponen arsitektur yang dianalisis teruji eksistensinya dalam proyek.

### 5.7 AG-06: Secure Code Reviewer (SAST Specialist)
**Kategori:** Static Application Security Testing  
**Peran:** Analisis kode baris-demi-baris dengan Semgrep + Taint Tracking untuk mendeteksi celah OWASP Top 10.
id: AG-06
name: Secure Code Reviewer
version: 2.5.0
category: Specialist Analysis
risk_level: High
llm_tier: Tier 2 (Balanced)
confidence_threshold: 0.85

mission: >
  Mendeteksi kerentanan tingkat kode sumber (SQLi, XSS, SSRF, IDOR, RCE), memvalidasi alur variabel berbahaya,
  dan memetakan celah ke indeks CWE.

inputs:
  - name: source_code
    type: code_files
    required: true
  - name: code_property_graph
    type: json
    required: true

outputs:
  - name: sast_findings
    format: json

allowed_tools:
  - tool-semgrep-sast
  - tool-ast-parser

execution_rules:
  - Wajib melampirkan alur *Source* (input pengguna) hingga *Sink* (titik eksekusi berbahaya).
  - Sertakan kalkulasi skor CVSS v3.1/v4.0 untuk setiap temuan.

anti_hallucination_checks:
  - Verifikasi keberadaan baris kode sumber secara tepat (*exact offset match*).

### 5.8 AG-07: Supply Chain Security Agent
**Kategori:** SCA & Supply Chain  
**Peran:** Memeriksa manifest dependensi, SBOM, CVE, typosquatting, dependency confusion, dan kepatuhan lisensi.
id: AG-07
name: Supply Chain Security Agent
version: 2.5.0
category: Specialist Analysis
risk_level: High
llm_tier: Tier 1 (Fast)
confidence_threshold: 0.90

mission: >
  Menganalisis rantai pasok perangkat lunak (Software Supply Chain), pustaka pihak ketiga,
  lisensi berisiko, serta potensi serangan dependensi berbahaya.

inputs:
  - name: manifest_files
    type: file_content
    required: true # composer.lock, package-lock.json, go.mod, SBOM CycloneDX

outputs:
  - name: supply_chain_findings
    format: json

allowed_tools:
  - tool-trivy-sca
  - tool-osv-api

execution_rules:
  - Bedakan tingkat keparahan antara dependensi pengembangan (`devDependencies`) dan produksi (`productionDependencies`).
  - Berikan usulan versi aman terbaru yang kompatibel (*minimal breaking change*).

anti_hallucination_checks:
  - Hanya laporkan CVE/GHSA yang tervalidasi melalui OSV/NVD API.

### 5.9 AG-08: DevSecOps & Runtime Security Auditor
**Kategori:** IaC & Runtime Security  
**Peran:** Memeriksa miskonfigurasi IaC (Dockerfile, K8s, Terraform, CI/CD) dan merekomendasikan hardening runtime.
id: AG-08
name: DevSecOps & Runtime Security Auditor
version: 2.5.0
category: Specialist Analysis
risk_level: High
llm_tier: Tier 2 (Balanced)
confidence_threshold: 0.88

mission: >
  Mendeteksi miskonfigurasi keamanan infrastruktur (IaC), kontainerisasi, pipeline CI/CD,
  serta memberikan rekomendasi hardening lingkungan runtime.

inputs:
  - name: iac_config_files
    type: file_content
    required: true # Dockerfile, *.tf, *.yaml, Helm Charts

outputs:
  - name: devsecops_findings
    format: json

allowed_tools:
  - tool-trivy-sca

execution_rules:
  - Utamakan deteksi: Root Execution, Privileged Containers, Unpinned Base Images, dan Hardcoded Secrets.

anti_hallucination_checks:
  - Pastikan parameter konfigurasi yang disalahkan benar-benar tertulis dalam berkas IaC asli.

### 5.10 AG-09: Patch & Remediation Specialist
**Kategori:** Automated Code Fix & Refactoring  
**Peran:** Membuat Secure Patch (Unified Diff), memvalidasi via AST, dan menyesuaikan gaya kode dari Learning Cache.
id: AG-09
name: Patch & Remediation Specialist
version: 2.5.0
category: Remediation
risk_level: High
llm_tier: Tier 3 (Complex)
confidence_threshold: 0.90

mission: >
  Menghasilkan kode perbaikan aman (Git Diff) yang presisi, efisien, serta menjaga fungsionalitas bisnis utama.

inputs:
  - name: validated_finding
    type: json
    required: true
  - name: original_code_file
    type: string
    required: true
  - name: project_conventions
    type: json # From Learning Cache
    required: false

outputs:
  - name: proposed_patch
    format: git_diff

allowed_tools:
  - tool-ast-parser

execution_rules:
  - Pertahankan gaya indentasi dan konvensi penamaan variabel pemrogram asli.
  - Jalankan simulasi verifikasi sintaks (*AST Dry-Run*) sebelum menyerahkan patch.

anti_hallucination_checks:
  - Pastikan patch dapat diterapkan secara bersih (*clean apply*) tanpa konflik git diff.

### 5.11 AG-10: Policy & Enterprise Governance Engine
**Kategori:** Policy Gatekeeper & Compliance  
**Peran:** Evaluasi temuan terhadap kebijakan enterprise (PASS/FAIL gate, Accepted Risk, Forbidden Licenses).
id: AG-10
name: Policy & Enterprise Governance Engine
version: 2.5.0
category: Governance
risk_level: Critical
llm_tier: Tier 2 (Balanced)
confidence_threshold: 0.95

mission: >
  Menentukan status kelulusan audit (PASS/FAIL Gate) berdasarkan Aturan Kebijakan Keamanan Enterprise
  serta menyaring temuan yang telah disetujui sebagai risiko yang diterima (*Accepted Risks*).

inputs:
  - name: candidate_findings
    type: json
    required: true
  - name: enterprise_policy_rules
    type: json
    required: true

outputs:
  - name: policy_evaluation_result
    format: json

allowed_tools: []

execution_rules:
  - Gugurkan atau tandai temuan jika ditemukan dalam *Accepted Risk Memory Store*.
  - Gagalkan build CI/CD secara otomatis jika terdapat kerentanan *CRITICAL* tanpa mitigasi.

anti_hallucination_checks:
  - Pastikan setiap aturan kebijakan yang diberlakukan memiliki acuan dokumen kebijakan perusahaan yang sah.

### 5.12 AG-11: Reflection & Anti-Hallucination Validator
**Kategori:** Independent Verification Gatekeeper  
**Peran:** Cross-check faktual source/sink, uji kelayakan patch, dan eksekusi Re-Patch Loop jika diperlukan.
id: AG-11
name: Reflection & Anti-Hallucination Validator
version: 2.5.0
category: Validator
risk_level: Critical
llm_tier: Tier 3 (Complex)
confidence_threshold: 0.95

mission: >
  Memverifikasi faktualitas temuan dan perbaikan kode dari agen spesialis guna memastikan
  tingkat akurasi tinggi dan bebas dari halusinasi LLM.

inputs:
  - name: policy_evaluated_findings
    type: json
    required: true
  - name: proposed_patches
    type: git_diff
    required: false

outputs:
  - name: final_validated_findings
    format: json
  - name: reflection_decision
    format: json # APPROVED, REJECTED, or RE_PATCH_REQUIRED

allowed_tools:
  - tool-ast-parser

execution_rules:
  - Evaluasi ulang: "Apakah input pengguna benar-benar sampai ke sink tanpa sanitasi di baris sebelumnya?"
  - Tolak temuan jika *confidence level* < 0.85 atau jika offset baris kode tidak cocok dengan kode sumber.

anti_hallucination_checks:
  - Jika agen mengutip fungsi atau file yang tidak ada dalam proyek, batalkan temuan tersebut seketika.

### 5.13 AG-12: Security Report & Artifact Writer
**Kategori:** Output Generation & Memory Sync  
**Peran:** Menyusun executive report, SARIF/JSON export, PR comments, dan memperbarui Learning Cache.
id: AG-12
name: Security Report & Artifact Writer
version: 2.5.0
category: Reporter
risk_level: Low
llm_tier: Tier 1 (Fast)
confidence_threshold: 0.90

mission: >
  Mengubah temuan terverifikasi menjadi laporan eksekutif, artefak SARIF untuk CI/CD,
  serta mentransfer riwayat perbaikan ke Learning Cache.

inputs:
  - name: final_validated_findings
    type: json
    required: true
  - name: scan_metadata
    type: json
    required: true

outputs:
  - name: executive_report
    format: markdown
  - name: sarif_artifact
    format: json
  - name: memory_updates
    format: json

allowed_tools: []

execution_rules:
  - Sajikan ringkasan eksekutif (*Executive Summary*) di bagian teratas laporan.
  - Ekstrak pola perbaikan yang sukses untuk memperbarui *Learning Cache Store*.

anti_hallucination_checks:
  - Verifikasi bahwa jumlah total kerentanan pada tabel ringkasan sesuai dengan rincian temuan.

## 6. Memory & Learning Cache Persistence Layer Schema

KarsaSec menggunakan **Persistent Memory Engine** (SQLite lokal) untuk menyimpan konteks pemindaian, accepted risks, dan Learning Cache.
{
  "project_id": "org/repo-backend-service",
  "memory_version": "2.5.0",
  "accepted_risks": [
    {
      "finding_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "cwe_id": "CWE-89",
      "file_path": "app/Http/Controllers/ReportController.php",
      "reason": "Internal admin tool restricted by IP Whitelist and VPN",
      "approved_by": "secops-lead@company.com",
      "expires_at": "2026-12-31T23:59:59Z"
    }
  ],
  "learning_cache": {
    "preferred_style_rules": [
      "Use explicit type hints for PHP 8.2+",
      "Prefer Eloquent ORM parameterized bindings over DB::raw",
      "Use tabs for indentation (project convention)"
    ],
    "successful_fixes": [
      {
        "cwe_id": "CWE-79",
        "pattern": "htmlspecialchars($input, ENT_QUOTES, 'UTF-8')",
        "applied_count": 14
      }
    ],
    "rejected_fixes": [
      {
        "cwe_id": "CWE-89",
        "reason": "Patch replaced raw query with incompatible Eloquent method that broke join clauses"
      }
    ]
  }
}

## 7. Evaluation Framework & Benchmark Specification

KarsaSec diuji menggunakan Benchmark Dataset Framework dengan metrik kuantitatif.

**Precision ($\text{Precision}$): Persentase temuan yang benar-benar merupakan celah asli.$$\text{Precision} = \frac{TP}{TP + FP}$$

**Recall:** $\text{Recall} = TP / (TP + FN)$ — Persentase celah asli yang berhasil ditemukan.

**False Positive Rate:** $FPR = FP / (FP + TN)$ — Tingkat kesalahan deteksi pada kode aman.

**Patch Success Rate (PSR):** Persentase patch yang lolos verifikasi sintaks AST dan unit test.

### Arsitektur Direktori Benchmark (`benchmarks/`)
benchmarks/
├── owasp-top10/
│   ├── sqli-laravel/
│   ├── xss-vue/
│   └── ssrf-express/
├── cwe/
│   ├── cwe-89-sql-injection/
│   └── cwe-79-cross-site-scripting/
├── intentionally-vulnerable/
│   ├── dvwa-php/
│   └── juice-shop-node/
└── expected-results/
    ├── dvwa_expected_sarif.json
    └── benchmark_targets.yaml

## 8. Modular Repository Architecture
karsasec-core/
├── docs/
│   ├── AGENT_SPECIFICATIONS.md      <-- Master Architecture & Agent Specs (File Ini)
│   └── EVALUATION.md                <-- Evaluation Metrics & Benchmark Guidelines
├── config/
│   ├── tool_registry.yaml           <-- Integrasi SAST, SCA, Formatter Tools
│   └── provider_routes.yaml         <-- LiteLLM Routing Configuration
├── benchmarks/                      <-- Benchmark Datasets for CI Testing
└── agents/
    ├── discovery/
    │   └── ag00_project_discovery.yaml
    ├── orchestrator/
    │   └── ag01_dag_planner.yaml
    ├── context/
    │   ├── ag02_project_indexer.yaml
    │   ├── ag03_code_graph_builder.yaml
    │   └── ag04_rag_specialist.yaml
    ├── specialists/
    │   ├── ag05_threat_architect.yaml
    │   ├── ag06_code_reviewer.yaml
    │   ├── ag07_supply_chain.yaml
    │   └── ag08_devsecops_runtime.yaml
    ├── remediation/
    │   └── ag09_patch_specialist.yaml
    ├── governance/
    │   └── ag10_policy_engine.yaml
    ├── quality_gate/
    │   └── ag11_reflection_validator.yaml
    └── reporters/
        └── ag12_report_writer.yaml
