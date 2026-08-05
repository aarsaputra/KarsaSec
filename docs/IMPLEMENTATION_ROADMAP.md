# 🗺️ KarsaSec — Implementation Roadmap

**Platform:** KarsaSec AI Application Security Operating System (SecOS)  
**Versi Roadmap:** 1.1.0 | **Terakhir Diperbarui:** 2026-08-05  
**Strategi MVP:** 4 Core Agents (`Planner` → `Analyzer` → `Remediator` → `Reporter`) + Dynamic Taint/Guard Verification

---

## 🎯 Visi & Strategi Eksekusi

Roadmap ini memandu pengembangan **KarsaSec** dari fondasi repositori hingga platform enterprise yang siap produksi. Berbeda dari dokumen arsitektur tinggi, roadmap ini berfokus pada **incremental working code** di mana setiap sprint menghasilkan biner/modul yang dapat dieksekusi dan diuji.

---

## 🚀 Ringkasan Sprint Overview

| Sprint | Nama Sprint | Fokus Utama & Output Kunci | Status |
|---|---|---|---|
| **Sprint 0** | Repository Foundation | `pyproject.toml` (Hatchling), Ruff, Mypy, Pytest, pre-commit, CI Actions | ✅ Completed |
| **Sprint 1** | CLI Core & Dependency Container | `typer` CLI, Rich UI, `Pydantic-Settings`, Core DI Container & Plugin Registry | ✅ Completed |
| **Sprint 2** | AST Parser & Language Detector | Engine `tree-sitter` Python bindings, multi-language detection | ✅ Completed |
| **Sprint 3** | Deterministic Rule Engine | YAML Rule Matcher (Loader, Validator, Matcher, Executor), Semgrep Adapter | ✅ Completed |
| **Sprint 4** | Code Property Graph (CPG) & Dataflow | SQLite-based graph storage, Call Graph, Data Flow Graph (DFG) traversal | ✅ Completed |
| **PQP v1.0** | Taint Analysis & Guard Verifier | Precision Engine, Static Sink Downgrade, Whitelist Guard Verification, IaC Exemption | ✅ Completed |
| **Sprint 5** | Hybrid RAG Search Engine | `Model2Vec` static embeddings, BM25 lexical search, Reciprocal Rank Fusion | ✅ Completed |
| **Sprint 6** | AI Provider Gateway Interface | Interface `AIProvider` (OpenAI, Gemini, Anthropic, Ollama), LiteLLM Adapter | ⏳ Planned |
| **Sprint 7** | 4-Agent Orchestrator State Machine | Core 4-Agent Pipeline (`Planner`, `Analyzer`, `Remediator`, `Reporter`) via State Machine | ⏳ Planned |
| **Sprint 8** | Auto-Patch Generator & Verification | AST Validation, Linting, Formatting, Unified Diff Patch Synthesizer | ⏳ Planned |
| **Sprint 9** | Enterprise Output, SARIF & CI/CD | SARIF v2.1 export, GitHub Action runner, JSON/Markdown reporting | ✅ Completed |

---

## 📋 Detail Rencana Sprint

### Sprint 0: Repository Foundation
- **Fokus:** Menyiapkan *tooling* dan infrastruktur repositori sejak awal agar *maintenance* di kemudian hari berjalan mulus.
- **Komponen Kunci:**
  - `pyproject.toml` dengan build-backend `hatchling`
  - Konfigurasi `ruff` (linter/formatter super cepat)
  - Konfigurasi `mypy` (strict type checking)
  - Konfigurasi `pytest` & `coverage`
  - `.editorconfig`, `.gitignore`
- **Output:** Repositori yang dapat di-install via `pip install -e .` dan lulus pengujian linter.

### Sprint 1: CLI Core, Config & Dependency Injection
- **Fokus:** Membangun antarmuka CLI yang elegan dan arsitektur `core/` untuk dependency injection dan plugin registry.
- **Komponen Kunci:**
  - `karsasec/cli.py`: Perintah `karsasec scan`, `review`, `fix`, `doctor`, `version` berbasis `typer` + `rich` UI
  - `karsasec/config.py`: Pengelolaan konfigurasi berbasis `pydantic-settings` (`.env`, `karsasec.yaml`)
  - `karsasec/core/container.py`: IoC Container untuk pendaftaran dependensi
  - `karsasec/core/registry.py`: Component Registry untuk parser, rule, dan provider
  - `karsasec/core/plugin.py`: Base Abstract Class untuk Plugin Loader
- **Output:** CLI `karsasec` dapat dijalankan di terminal dengan opsi Rich formatting dan sistem DI yang siap pakai.

### Sprint 2: AST Parser & Language Detector
- **Fokus:** Kemampuan membaca kode sumber dan mengonversi menjadi Abstract Syntax Tree (AST) secara deterministik.
- **Komponen Kunci:**
  - `karsasec/parser/detector.py`: Deteksi otomatis bahasa & framework (Python, PHP, JS/TS, Go, Rust, Java)
  - `karsasec/parser/tree_sitter.py`: Wrapper multi-bahasa berbasis bindings Python `tree-sitter`
  - `karsasec/parser/ast_nodes.py`: DTO representasi Node AST seragam
- **Output:** Ekstraksi fungsi, kelas, impor, dan variabel dari berkas sumber proyek.

### Sprint 3: Deterministic Rule Engine
- **Fokus:** Pencocokan aturan keamanan berbasis AST dan pola OWASP/CWE sebelum memanggil AI.
- **Komponen Kunci:**
  - `RuleLoader`: Memuat aturan YAML dari direktori `rules/`
  - `RuleValidator`: Verifikasi skema sintaks aturan kustom
  - `RuleMatcher`: Matcher pola AST (Source, Sink, Sanitizer)
  - `RuleExecutor`: Engine pemindai paralel untuk ribuan aturan
- **Output:** Deteksi kerentanan awal deterministik dengan *zero false positives* pada pola yang pasti.

### Sprint 4: Code Property Graph (CPG)
- **Fokus:** Penyimpanan relasi antar-simbol kode ke basis data SQLite lokal.
- **Komponen Kunci:**
  - `karsasec/graph/db.py`: SQLite single-file database manager (`codebase_memory.db`)
  - `karsasec/graph/builder.py`: Penyiapan tabel `nodes`, `call_edges`, `import_maps`
  - `karsasec/graph/traversal.py`: Query helper untuk penelusuran Source-to-Sink (DFG & Call Graph)
- **Output:** Traversal alur variabel lintas fungsi dan modul tanpa *hallucination*.

### Sprint 5: Hybrid RAG Search Engine
- **Fokus:** Pencarian kontekstual super cepat untuk RAG keamanan tanpa butuh GPU atau cloud API.
- **Komponen Kunci:**
  - `karsasec/rag/bm25.py`: Lexical BM25 search engine
  - `karsasec/rag/model2vec.py`: Static embedding CPU-bound (`Model2Vec`)
  - `karsasec/rag/hybrid.py`: Fusion via Reciprocal Rank Fusion (RRF)
- **Output:** Retrieval chunk kode dan referensi CWE/CVE dengan latensi mendekati 0ms.
- **Status:** Initial hybrid retrieval engine implemented; CLI support for `karsasec scan --rag` added and local corpus indexing enabled from `security_corpus/`.

### Sprint 6: AI Provider Gateway Interface
- **Fokus:** Abstraksi lapisan komunikasi LLM agar tidak terikat langsung ke penyedia tertentu.
- **Komponen Kunci:**
  - `karsasec/ai/base.py`: Interface `AIProvider` (ABC)
  - `karsasec/ai/litellm_provider.py`: Implementasi adapter LiteLLM
  - `karsasec/ai/custom_providers/`: Adapter langsung OpenAI, Gemini, Anthropic, Ollama
  - `karsasec/ai/router.py`: Cost-aware fallback router & token budget controller
- **Output:** Lapisan inferensi LLM fleksibel yang mendukung cloud LLM dan model lokal.

### Sprint 7: Core 4-Agent Orchestrator State Machine
- **Fokus:** Orkestrasi multi-agen MVP menggunakan alur State Machine yang stabil.
- **State Flow:** `INIT` → `PLAN` → `ANALYZE` → `FIX` → `VERIFY` → `REPORT` → `END`
- **4 Core Agents:**
  - `PlannerAgent`: Membedah target audit dan menyusun skenario eksekusi
  - `AnalyzerAgent`: Menjalankan SAST, CPG traversal, SCA, dan evaluasi sanitasi
  - `RemediatorAgent`: Mensintesis perbaikan kode aman
  - `ReporterAgent`: Format laporan akhir
- **Output:** Audit keamanan otomatis end-to-end dengan 4 agen terspesialisasi.

### Sprint 8: Auto-Patch Generator & Verification
- **Fokus:** Perbaikan kode otomatis yang tervalidasi sintaks dan keselamatannya.
- **Komponen Kunci:**
  - `karsasec/agents/remediator.py`: Generasi Unified Git Diff (`.patch`)
  - `karsasec/parser/validator.py`: AST dry-run check & syntax error validation
  - `karsasec/utils/linter.py`: Uji lint & formatting gaya penulisan proyek
- **Output:** Kode perbaikan aman yang bebas dari *syntax error* dan menjaga konvensi kode asli.

### Sprint 9: Enterprise Output, SARIF & CI/CD
- **Fokus:** Integrasi ke alur kerja CI/CD dan ekspor laporan standar industri.
- **Komponen Kunci:**
  - `karsasec/output/sarif.py`: Generator SARIF v2.1.0 untuk GitHub Security Tab
  - `karsasec/output/markdown.py`: Ringkasan eksekutif ramah developer
  - `action.yml`: Runner GitHub Action resmi KarsaSec
- **Output:** KarsaSec dapat dipasang langsung di GitHub Actions / GitLab CI dengan progressive security gating.

---

## 🧪 Kriteria Kualitas & Testing

Setiap Sprint wajib menyertakan:
1. **Unit Test (`pytest`)** — Cakupan pengujian minimal 80% untuk fungsi internal.
2. **Integration Test** — Pengujian CLI end-to-end pada contoh repositori rentan.
3. **Snapshot Test** — Verifikasi kestabilan Rich Console UI.
4. **Golden File Test** — Memastikan keabsahan skema JSON dan SARIF output.
5. **Performance Benchmark** — Memastikan pemindaian aturan deterministik berjalan dalam hitungan milidetik.
