# 🛡️ KarsaSec — Project Blueprint v2.0

**Brand:** KarsaSec
**Tagline:** AI Software Security Engineer
**Kategori:** Autonomous Application Security Operating System (SecOS)
**CLI Binary:** `karsasec` | **PyPI Package:** `karsasec`
**Target Domain:** `karsasec.ai` / `karsasec.dev`
**Versi Dokumen:** 2.0 | **Terakhir Diperbarui:** 2026-08-04

---

## 1. Vision & Mission

### Vision

Membangun KarsaSec sebagai **Security Operating System (SecOS)** open-source pertama yang menyatukan seluruh infrastruktur keamanan aplikasi — mulai dari parsing AST deterministik, pemindaian statis, rule engine, hingga penalaran multi-agen AI — guna mendampingi pengembang di sepanjang **Secure Software Development Lifecycle (SSDLC)**.

### Mission

KarsaSec tidak menjual model AI atau chatbot, melainkan menyediakan **Operating System Keamanan** yang mampu menghasilkan analisis keamanan aplikasi yang dapat dijelaskan (*explainable*), berbasis bukti (*evidence-based*), dan dapat ditindaklanjuti (*actionable*) melalui orkestrasi:

- **Deterministic Static Analysis & AST Parsing Engine** — Rule matching berbasis kode nyata, bukan inferensi murni
- **Security Rule Engine & Custom Policy Enforcement** — Aturan OWASP/CWE/company policy yang dapat dikonfigurasi
- **Codebase Context Builder & Knowledge Memory** — Knowledge graph lokal berbasis Tree-sitter + SQLite
- **Multi-Agent AI Reasoning & Reflection Architecture** — Orkestrasi agen spesialis via DAG Workflow
- **Automated Patch Synthesis & Verification** — LLMLOOP iteratif dengan validasi kompilasi dan sandbox runtime

---

## 2. Problem Statement

Tim rekayasa perangkat lunak modern dihadapkan pada **fragmentasi perkakas keamanan** (*security tooling fatigue*):

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   Semgrep   │   │   CodeQL    │   │    Trivy    │   │  Gitleaks   │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │                 │
┌──────┴──────┐   ┌──────┴──────┐   ┌──────┴──────┐   ┌──────┴──────┐
│ SonarQube   │   │  npm/pip    │   │    OWASP    │   │  CVE / NVD  │
│             │   │    audit    │   │ Cheat Sheets│   │  Databases  │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
                                   │
                                   ▼
                      Developer Cognitive Overload
                (False Positives · Dispersed Context ·
               Unprioritized Vulnerabilities · No Fixes)
```

**Pain Points Utama:**

| Pain Point | Dampak |
|---|---|
| **Fragmentasi Informasi** | Temuan tersebar di banyak CLI output, dashboard, dan laporan terpisah |
| **Kehilangan Konteks** | Scanner generik tidak memahami logika bisnis dan arsitektur aplikasi |
| **Kebisingan & False Positive Tinggi** | Developer membuang waktu bertriage temuan yang tidak bisa dieksploitasi |
| **Tidak Ada Panduan Remediasi** | Tools melaporkan *apa* yang salah, tapi jarang menunjukkan *cara* perbaikan yang aman dan kontekstual |

**KarsaSec hadir sebagai Security Operating System** yang mengonsolidasi seluruh lapisan tersebut ke dalam satu *runtime* terintegrasi.

---

## 3. Core Architecture: The SecOS Paradigm

Dalam arsitektur KarsaSec, AI hanyalah *satu komponen* dari keseluruhan sistem operasi. Platform dibagi menjadi **12 lapisan modular** yang saling terhubung:

| Layer | Nama Komponen | Fungsi & Tanggung Jawab Utama |
|---|---|---|
| **Layer 1** | Interface Layer | Mengelola interaksi pengguna melalui CLI Native (`karsasec`), IDE Extension (VS Code), API Server, dan CI/CD Runner |
| **Layer 2** | Plugin Engine | Memuat parser bahasa (`plugins/python`, `php`, `go`), scanner eksternal, dan AI provider via antarmuka modular |
| **Layer 3** | Context Builder | Mengonstruksi objek konteks utuh dari AST, repositori, dependensi, konfigurasi, secret, dan riwayat git |
| **Layer 4** | Rule Engine | Mengeksekusi aturan deterministik berbasis AST (OWASP, CWE, company policy) **sebelum** AI dipanggil |
| **Layer 5** | Knowledge Base (RAG) | Menyediakan referensi standar keamanan, database CVE/NVD/OSV, dan dokumen framework via Knowledge Graph |
| **Layer 6** | Memory Layer | Menyimpan memori pemindaian terdahulu, umpan balik developer, patch lama, serta status accepted risk |
| **Layer 7** | Planner Agent | Membedah tugas audit besar menjadi sub-tugas terstruktur (*task decomposition*) berbasis DAG |
| **Layer 8** | Persona Router | Menghubungkan tugas terencana ke agen spesialis AppSec yang paling relevan |
| **Layer 9** | Specialist Agents | Menjalankan penalaran spesifik (SAST, Threat Modeler, DevSecOps) via protokol MCP |
| **Layer 10** | Reasoning Engine | Menganalisis bukti, menghitung dampak bisnis, dan menyusun rekomendasi |
| **Layer 11** | Reflection Engine | Melakukan verifikasi mandiri dan Re-Patch Loop pada patch yang dihasilkan |
| **Layer 12** | Reporting & Patch Engine | Menerbitkan laporan terstruktur, anotasi PR, dan patch perbaikan tervalidasi |

---

## 4. Multi-Agent Orchestration & Graph Workflow

KarsaSec mengadopsi **Execution Graph interaktif** berbasis DAG, menggantikan alur kerja linier. Alur dari permintaan pengguna hingga output akhir:

| # | Tahap Alur Kerja | Komponen | Deskripsi Proses |
|---|---|---|---|
| 1 | **Trigger & Ingestion** | Event Bus | Menerima pemicu dari CLI, CI/CD webhook, atau IDE extension |
| 2 | **Project Discovery** | AG-00: Project Discovery Agent | Mendeteksi bahasa, framework, build system, dan struktur repositori |
| 3 | **DAG Planning** | AG-01: Workflow DAG Planner | Merancang grafik eksekusi terarah, alokasi token budget, dan rute model LLM |
| 4 | **Repository Indexing** | AG-02: Project Indexer Agent | Mengklasifikasi struktur direktori dan membuat indeks simbol global |
| 5 | **Code Graph Building** | AG-03: Code Property Graph Builder | Membangun AST, Call Graph, Route-to-Controller Mapping, Source-to-Sink dataflow |
| 6 | **Knowledge Grounding** | AG-04: Knowledge & RAG Specialist | Mengambil CWE, CVE/GHSA, OWASP, dan dokumen framework dari Knowledge Base |
| 7 | **Specialist Parallel Execution** | AG-05 s/d AG-08 (Paralel) | Threat Model, SAST, Supply Chain, dan DevSecOps audit berjalan paralel |
| 8 | **Patch Synthesis** | AG-09: Patch & Remediation Specialist | Membuat Unified Diff perbaikan berdasarkan temuan terverifikasi |
| 9 | **Policy Gating** | AG-10: Policy & Governance Engine | Mengevaluasi temuan terhadap kebijakan enterprise (PASS/FAIL gate) |
| 10 | **Reflection & Validation** | AG-11: Reflection & Validator | Cross-check faktual, eliminasi false positive, Re-Patch Loop jika diperlukan |
| 11 | **Output Delivery** | AG-12: Security Report Writer | Menerbitkan laporan CLI, SARIF/JSON, anotasi PR, dan memperbarui Memory Store |

---

## 5. Context Builder Engine

Sebelum AI diberi tugas menganalisis kode, **Context Builder Engine** mengekstraksi seluruh artefak teknis repositori untuk membentuk satu `UnifiedContextObject`:

**Komponen Ekstraksi (7 Tahap Berurutan):**

1. **Language Detection** — Memindai ekstensi file (`.py`, `.go`, `.php`, `.rs`, `.ts`) untuk menentukan parser bahasa utama
2. **Framework Detection** — Membaca berkas impor dan konfigurasi untuk mengenali framework aktif (Laravel, Django, Express, Go Fiber, Spring Boot)
3. **Dependency Detection** — Membaca berkas manifest (`requirements.txt`, `composer.json`, `package.json`, `go.mod`, `Cargo.toml`)
4. **Infrastructure & Config Scanning** — Membaca `Dockerfile`, Kubernetes manifest, Terraform, CI/CD pipeline scripts
5. **Secrets & Credentials Context** — Memindai pola kunci API, token, dan sertifikat yang terekspos
6. **AST & Call Graph Generation** — Menjalankan parser Tree-sitter untuk membangun peta fungsi dan *call graph* inter-modul
7. **Git History & Diff Analysis** — Mengidentifikasi baris kode yang berubah pada commit atau Pull Request aktif

---

## 6. Security Rule Engine & Policy System

AI di KarsaSec **tidak bekerja berdasarkan intuisi semata**, melainkan selalu dibimbing oleh Rule Engine deterministik yang dieksekusi lebih dahulu.

**Struktur Direktori Rules (`rules/`):**

```
rules/
├── owasp/          # Aturan pencocokan pola OWASP Top 10 & OWASP API Security Top 10
├── cwe/            # Definisi pemeriksaan kerentanan spesifik katalog CWE
├── framework/      # Aturan praktik terbaik keamanan per framework (Django, Spring, Express)
├── organization/   # Kebijakan keamanan internal perusahaan (mis. "Larang MD5 di seluruh service")
└── custom/         # Aturan buatan pengembang via Custom Rule DSL KarsaSec
```

Rule Engine mengeksekusi pemeriksaan AST secara cepat. Jika pola berbahaya ditemukan (mis. variabel tak tersanitasi masuk ke kueri SQL), kandidat temuan ditandai dan diteruskan ke AI Reasoning Engine untuk verifikasi konteks tingkat lanjut.

---

## 7. Security Reasoning Engine

**Security Reasoning Engine** mengonversi temuan mentah menjadi wawasan keamanan berstandar enterprise melalui pipeline penalaran 6 tahap:

| Tahap | Proses |
|---|---|
| **Evidence Gathering** | Mengumpulkan bukti fisik dari kode sumber (baris kode, jalur AST, rantai pemanggilan fungsi) |
| **Dataflow & Sanitization Analysis** | Menelusuri jalur variabel dari *source* ke *sink* untuk mengecek keberadaan fungsi sanitasi |
| **Risk & Business Impact Analysis** | Mengalkulasi potensi dampak terhadap kerahasiaan (C), integritas (I), dan ketersediaan (A) |
| **Confidence Scoring** | Memberikan skor keyakinan (0.0–1.0) berbasis bukti fisik dan verifikasi alur data |
| **Multi-Factor Prioritization** | Menghitung skor prioritas riil menggabungkan bobot CVSS v4.0, estimasi EPSS, dan status CISA KEV |
| **Actionable Recommendation & Patch** | Menyusun panduan perbaikan jelas dan sintesis patch kode yang siap di-merge |

**Formula Prioritasi KarsaSec:**

$$\text{Priority Score} = (0.5 \times \text{CVSS}_{\text{v4.0}}) + (0.3 \times \text{EPSS}) + (0.2 \times \text{KEV}_{\text{flag}})$$

> Di mana `KEV_flag = 1.0` jika CVE tercantum dalam katalog CISA KEV, dan `0.0` jika tidak ada.

---

## 8. AI Provider Abstraction Layer

KarsaSec sepenuhnya **vendor-agnostic**. Semua permintaan inferensi LLM melewati **LiteLLM AI Gateway** sebagai middleware terpusat:

```
┌───────────────────────────────────┐
│    LiteLLM Unified Interface     │
└─────────────────┬─────────────────┘
                  │
    ┌─────────────┼─────────────┐
    ▼             ▼             ▼
┌─────────┐ ┌──────────┐ ┌──────────┐
│ OpenAI  │ │Anthropic │ │  Google  │
│  (GPT)  │ │ (Claude) │ │ (Gemini) │
└─────────┘ └──────────┘ └──────────┘
    ▼             ▼             ▼
┌─────────┐ ┌──────────┐ ┌──────────┐
│DeepSeek │ │   Qwen   │ │  Ollama  │
│  /vLLM  │ │ (Local)  │ │  (Local) │
└─────────┘ └──────────┘ └──────────┘
```

**Fitur Gateway:**
- **Dynamic Failover Routing** — Otomatis beralih ke model alternatif saat rate limit 429 atau 5xx
- **Per-Session Token Budgeting** — Batas token per sesi audit untuk mencegah *runaway cost*
- **Tier-Based Model Routing** — Tiga tier kapabilitas (Fast / Balanced / Complex) sesuai kompleksitas tugas
- **Prompt Injection Guardrails** — Seluruh kode yang diaudit diperlakukan sebagai *untrusted data stream*

> **Catatan Implementasi:** Nama model konkret dan konfigurasi routing dikelola di `config/provider_routes.yaml`, bukan di-hardcode dalam source code. Ini memungkinkan pergantian model tanpa mengubah kode.

**Contoh `config/provider_routes.yaml`:**

```yaml
tiers:
  tier_1_fast:
    providers: [gemini-2.5-flash, gpt-4o-mini, deepseek-v3]
    max_tokens: 8000
    timeout_s: 20
  tier_2_balanced:
    providers: [claude-sonnet-latest, gpt-4o, deepseek-r1]
    max_tokens: 16000
    timeout_s: 60
  tier_3_complex:
    providers: [claude-sonnet-latest, o3-mini]
    max_tokens: 32000
    timeout_s: 120
```

---

## 9. Standardized Finding Schema

Setiap temuan yang diterbitkan KarsaSec mengikuti skema JSON/YAML terstruktur berikut:

```json
{
  "id": "KS-2026-0801",
  "title": "SQL Injection in User Search Endpoint",
  "severity": "CRITICAL",
  "cvss_score": 9.8,
  "cvss_version": "4.0",
  "epss_score": 0.94,
  "cisa_kev": false,
  "priority_score": 0.88,
  "cwe": "CWE-89",
  "owasp": "A03:2021 - Injection",
  "capec": "CAPEC-66",
  "file_path": "src/controllers/userController.js",
  "line_number": 42,
  "evidence": "db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`)",
  "taint_source": "req.query.name (HTTP GET parameter)",
  "taint_sink": "db.query() at line 42",
  "description": "User input langsung dikoncatenasi ke dalam string kueri SQL mentah tanpa sanitasi atau parameterisasi.",
  "attack_scenario": "Penyerang dapat menyisipkan payload `' OR '1'='1` pada parameter `name` untuk mengambil seluruh data pengguna.",
  "recommendation": "Gunakan parameterized queries atau ORM binding.",
  "suggested_patch": "db.query('SELECT * FROM users WHERE name = ?', [req.query.name])",
  "confidence_score": 0.96,
  "status": "Verified",
  "agent_id": "AG-06",
  "scan_id": "SCAN-2026-0801-001"
}
```

---

## 10. Plugin & Extension System

KarsaSec dibangun secara modular agar komunitas open-source dapat menambahkan parser, scanner, dan AI provider baru.

**Struktur Direktori Plugins (`plugins/`):**

```
plugins/
├── languages/      # Parser bahasa berbasis Tree-sitter (python/, php/, go/, java/, rust/, node/, dotnet/)
├── scanners/       # Integrasi scanner pihak ketiga (Semgrep, Trivy, Gitleaks, SonarQube)
├── providers/      # Abstraksi LLM Provider via LiteLLM (openai/, anthropic/, gemini/, ollama/, vllm/)
└── reporters/      # Format output kustom (SARIF, HTML, PDF, Jira, Slack)
```

**Plugin Interface API (`abc.ABC`):**

```python
from abc import ABC, abstractmethod
from typing import List, Dict, Any

class ParserPlugin(ABC):
    @abstractmethod
    def parse_ast(self, file_path: str) -> Dict[str, Any]:
        """Mengekstraksi AST dan simbol dari file sumber."""
        pass

class ScannerPlugin(ABC):
    @abstractmethod
    def run_scan(self, context: Any) -> List[Dict[str, Any]]:
        """Mengeksekusi aturan pemindaian dan mengembalikan kandidat finding."""
        pass

class ProviderPlugin(ABC):
    @abstractmethod
    def completion(self, prompt: str, model: str) -> str:
        """Mengirimkan prompt ke LLM provider dan mengembalikan respons."""
        pass

class ReporterPlugin(ABC):
    @abstractmethod
    def generate_report(self, findings: List[Dict[str, Any]], output_path: str) -> None:
        """Mengonversi temuan tervalidasi menjadi format laporan kustom."""
        pass
```

---

## 11. Memory Layer (Long-Term & Short-Term)

Memory Layer memastikan KarsaSec belajar dari konteks proyek dan tidak mengulang evaluasi yang sama pada setiap sesi pemindaian.

**Komponen Memori:**

| Komponen | Deskripsi |
|---|---|
| **Scan History** | Riwayat hasil audit sebelumnya tersimpan di SQLite lokal per-project |
| **Patch History** | Rekaman patch yang pernah dibuat beserta status keberhasilannya |
| **Developer Feedback Loop** | Catatan penolakan atau penerimaan rekomendasi oleh developer |
| **Accepted Risks Registry** | Daftar kerentanan yang secara resmi ditandai sebagai *Accepted Risk* atau *False Positive*, agar tidak memicu alarm di masa mendatang |
| **Learning Cache** | Konvensi penulisan kode proyek dan pola perbaikan yang berhasil, untuk meningkatkan kualitas patch selanjutnya |

---

## 12. Target Users

### Pengguna Primer

| Peran | Cara Menggunakan KarsaSec |
|---|---|
| **Backend / Frontend / Fullstack Engineer** | Menerima review keamanan real-time dan patch PR otomatis |
| **Software Engineer** | Belajar secure coding practices secara *inline* dalam alur kerja harian |

### Pengguna Sekunder

| Peran | Cara Menggunakan KarsaSec |
|---|---|
| **DevSecOps Engineer** | Audit pipeline CI/CD, Dockerfile, dan konfigurasi IaC |
| **AppSec & Security Engineer** | Mengotomasi triage berulang dan fokus pada ancaman kompleks |
| **QA Engineer** | Mengintegrasikan test case keamanan otomatis ke dalam test suite |

### Enterprise & Governance

| Peran | Cara Menggunakan KarsaSec |
|---|---|
| **Software Architect** | Validasi batasan arsitektur, model autentikasi, dan alur data |
| **Compliance & SOC Teams** | Memetakan postur keamanan aplikasi ke OWASP ASVS, NIST SSDF, dan ISO 27001 |
| **CTO / VP Engineering** | Mendapatkan visibilitas risiko keamanan lintas proyek dan tren hutang teknis |

---

## 13. Business Model

KarsaSec mengadopsi model **Open-Core** yang dirancang untuk menghasilkan kepercayaan komunitas sambil mendanai pengembangan enterprise-grade:

| Tier | Target | Model | Konten |
|---|---|---|---|
| **Community (Open Source)** | Developer individu, tim kecil | Gratis — Apache 2.0 | CLI `karsasec`, scanner SAST/SCA, rule engine OWASP/CWE, laporan Markdown/SARIF |
| **Professional** | Startup & tim engineering | Langganan per-seat | Semua Community + RAG lanjutan, integrasi IDE, sinkronisasi memori cloud, patch PR otomatis |
| **Enterprise** | Korporasi & BUMN | Kontrak tahunan | Semua Professional + dashboard analitik eksekutif, multi-repo federation, SLA 99.9%, audit trail, SSO/LDAP, custom compliance mapping |
| **Self-Hosted / Air-Gapped** | Lembaga keuangan, pertahanan | Lisensi enterprise | Seluruh platform + dukungan model lokal penuh (Ollama/vLLM), zero cloud dependency |

**Sumber Pendapatan Tambahan:**
- **Plugin Marketplace** — Komisi dari penjualan rule pack, parser framework, dan reporter kustom dari kontributor
- **Security Advisory Services** — Konsultasi implementasi dan pelatihan tim AppSec

---

## 14. Long-Term Roadmap

### Strategi Bahasa: Python-First, Rust-Accelerated

> Keputusan teknis ini menyelaraskan ADR-004 (`riset_karasec.md`) dengan kebutuhan kecepatan delivery MVP:
>
> - **Phase 1–2 (MVP):** Seluruh orkestrasi, agen, RAG, dan plugin API ditulis **Python 3.11+** menggunakan `typer`, `pydantic`, `litellm`, dan `tree-sitter` Python bindings. Ini memungkinkan iterasi cepat.
> - **Phase 3+ (Acceleration):** Komponen *hot-path* yang terbukti menjadi bottleneck secara empiris (parser AST, traversal knowledge graph skala besar) dimigrasikan ke **Rust** sebagai ekstensi biner statis (`pyo3` bindings). Single static binary menjadi target akhir.

| Phase | Milestone | Durasi Target |
|---|---|---|
| **Phase 1** | MVP CLI (`karsasec scan .`) + Tree-sitter Parser + Rule Engine SAST + Planner Agent | 0–4 bulan |
| **Phase 2** | Context Builder + Knowledge Graph (RAG) + Dependency Auditor + Memory Layer SQLite | 4–8 bulan |
| **Phase 3** | Multi-Agent Full Pipeline + DevSecOps Auditor + Policy Engine + Reflection Loop | 8–14 bulan |
| **Phase 4** | Auto-Patch Generator (`karsasec fix`) + LLMLOOP + PR Integration + Rust hot-path migration | 14–20 bulan |
| **Phase 5** | VS Code Extension + JetBrains Plugin + GitHub/GitLab App + Plugin Marketplace | 20–26 bulan |
| **Phase 6** | Enterprise Dashboard + Multi-repo Federation + Continuous Security Memory + Air-gapped mode | 26+ bulan |

---

## 15. Documentation Tree

Dokumentasi teknis KarsaSec terbagi menjadi dua layer:

### Layer 1: Top-Level Docs (`docs/`)

| File | Konten |
|---|---|
| `docs/PROJECT_BLUEPRINT.md` | Visi, arsitektur SecOS, dan peta jalan utama (dokumen ini) |
| `docs/AGENT_SPECIFICATIONS.md` | Spesifikasi lengkap 13 agen, skema metadata, tool registry |
| `docs/RESEARCH_FOUNDATION.md` | Fondasi riset arsitektur dan referensi akademis |
| `docs/CLI_REFERENCE.md` | Dokumentasi perintah CLI (`scan`, `review`, `fix`, `config`, `doctor`, `plugins`) |
| `docs/CONTRIBUTING.md` | Panduan kontribusi open-source, standar penulisan kode, dan pengujian |
| `docs/ROADMAP.md` | Peta jalan jangka panjang dengan milestone terukur |
| `docs/SECURITY.md` | Kebijakan pelaporan kerentanan, responsible disclosure |
| `docs/CHANGELOG.md` | Rekaman perubahan antar versi |

### Layer 2: Architecture Detail (`docs/architecture/`)

| File | Konten |
|---|---|
| `docs/architecture/01-system-overview.md` | Visi SecOS, komponen tingkat tinggi, dan Master Architecture Workflow |
| `docs/architecture/02-agent-system.md` | DAG Planner, Persona Router, 13 Specialist Agents, dan Reflection Loop |
| `docs/architecture/03-rag.md` | Arsitektur Knowledge Graph, Tree-sitter AST chunking, dan pencarian hibrida BM25 + Model2Vec |
| `docs/architecture/04-cli.md` | Desain antarmuka CLI, struktur perintah, dan pengelolaan output terminal |
| `docs/architecture/05-rule-engine.md` | Spesifikasi sintaks aturan deterministik, kategorisasi OWASP/CWE, dan penyaring AST |
| `docs/architecture/06-plugin-system.md` | Panduan API untuk `ParserPlugin`, `ScannerPlugin`, `ProviderPlugin`, `ReporterPlugin` |
| `docs/architecture/07-security-pipeline.md` | Detail integrasi SSDLC, *progressive gating* CI/CD, dan pembuatan anotasi PR |
| `docs/architecture/08-adr.md` | Architecture Decision Records (ADR-001 s/d ADR-005 + keputusan Python-First) |

---

## 16. Design Principles

| Prinsip | Deskripsi |
|---|---|
| **Security-First** | Prioritaskan *defense-in-depth* tanpa merusak kecepatan pengembangan fungsional |
| **Explainable AI** | Tidak ada temuan keamanan tanpa bukti konkret, referensi CWE, dan alasan yang dapat diaudit |
| **Evidence-Based** | Semua wawasan berasal dari struktur kode nyata, output analisis statis, dan dokumentasi RAG terverifikasi |
| **Provider-Agnostic** | Mendukung model lokal/open-source (Ollama/DeepSeek) setara dengan API komersial |
| **Modular Plugin Architecture** | Memungkinkan kontributor komunitas menambahkan AST rule, AI persona, dan framework parser kustom |
| **Developer Velocity** | Eksekusi cepat, latensi rendah, dan tanpa hambatan (*zero friction*) dalam alur kerja pengembangan harian |
| **Deterministic Grounding** | AI berfungsi sebagai *reasoning engine* yang dibatasi oleh bukti analisis statis — bukan sumber kebenaran mutlak |

---

*Dokumen ini merupakan satu-satunya sumber kebenaran (*single source of truth*) untuk visi dan arsitektur KarsaSec. Untuk spesifikasi teknis detail, lihat `docs/architecture/` dan `docs/AGENT_SPECIFICATIONS.md`.*
