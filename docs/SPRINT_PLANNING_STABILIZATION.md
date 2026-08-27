# Master Production Roadmap v6: Architecture Freeze & Production Hardening

Breakdown roadmap terstruktur berbasis **Architecture Freeze & Production Hardening**, dengan fokus penuh pada integrasi, stabilitas API, isolasi kegagalan, dan sertifikasi kualitas sebelum fase AI Consumer.

### 🏛️ Phase 1: Reusable Analysis Ecosystem & Governance
| Sprint | Fokus Capability | Target Output / Deliverables |
| :--- | :--- | :--- |
| **4B** | Stabilisasi Resolver | Portabilitas test suite & semantic resolver multi-import |
| **5.5** | Symbol Database & Indexing (`karsasec/index/`) | Persistent symbol store & multi-index lookup |
| **5.85** | Multi-Layered IR (`karsasec/ir/hir_mir.py`) | HIR (Syntax), MIR (Unified Semantics), LIR (Analysis Taint) |
| **6.85** | Query Optimizer (`karsasec/query/optimizer.py`) | Logical plan, predicate pushdown, & capability selection |
| **6.9** | Analysis Pass Manager (`karsasec/runtime/pass_manager.py`) | Pass contracts with failure isolation & time/memory budgets |
| **ADR** | Architecture Decision Records (`docs/adr/`) | ADR-0001 s/d ADR-0005 formal architecture governance |

### 🛠️ Phase 2: Architecture Consolidation & API Stabilization
| Sprint | Fokus Hardening | Target Output / Deliverables |
| :--- | :--- | :--- |
| **7** | Architecture Consolidation | Capability Integration Matrix & Artifact Ownership Contract (`docs/architecture/`) |
| **8** | Compatibility & API Stabilization | Analysis API Lifecycle (`Experimental -> Beta -> Stable`) & Multi-Schema Versioning |

### ⚡ Phase 3: Production Hardening & Quality Qualification
| Sprint | Fokus Hardening | Target Output / Deliverables |
| :--- | :--- | :--- |
| **9** | Production Hardening | Memory/time budgets, deterministic SHA-256 fingerprinting, & failure isolation |
| **10** | Platform Quality Qualification | Internal quality gates for Parser, IR, CFG, Dataflow, Rules, & Runtime |

### 🤖 Phase 4: Autonomous AI Consumer Layer
| Sprint | Fokus Capability | Target Output / Deliverables |
| :--- | :--- | :--- |
| **11** | Explainability AI (Read-Only) | Finding explanation & contextual summarization (Reads ArtifactStore) |
| **12** | Root Cause & Reflection (Read-Only) | Deep root cause analysis & evidence verification |
| **13** | Remediation & Patch Generation | Automated patch proposals with validator gatekeeper |
| **14** | Multi-Agent Orchestration | Specialist, Reviewer, & Policy agent orchestration |

---

## Sprint 4B — Stabilisasi & Perbaikan Bug Kritis
**Durasi:** ~2 minggu · **Prasyarat:** Sprint 4A (selesai, tapi ada regresi) · **Prioritas:** 🔴 Blocker

Tidak ada fitur baru di sprint ini — tujuannya membuat fondasi semantic resolver
benar-benar bisa dipercaya sebelum dibangun lebih jauh.

- `[ ]` **Fix 1: Portabilitas test suite**
  - `[ ]` Ganti path absolut di `tests/unit/rules/test_corpus_validation.py`
    (`/home/lota1337/python/KarsaSec/...`) menjadi relatif via `Path(__file__).resolve().parents[...]`
    atau `pytest` fixture `tmp_path`/`request.config.rootpath`.
  - `[ ]` Audit seluruh test lain untuk path hardcoded serupa (`grep -rn "/home/" tests/`).
  - `[ ]` Tambahkan job CI (GitHub Actions) yang menjalankan `pytest` dari clone bersih,
    bukan mengandalkan run manual di mesin developer.

- `[ ]` **Fix 2: Alias tracking untuk import multi-nama**
  - `[ ]` `karsasec/semantic/resolver.py::_process_imports` — perbaiki regex Python
    `import a, b` dan `from x import a, b as c` agar memproses **seluruh** nama dalam
    daftar, bukan cuma yang pertama.
  - `[ ]` Lakukan hal yang sama untuk pola setara di JS (`import {a, b as c} from 'x'`)
    dan Go (multi-import block `import (...)`), PHP (`use A, B;`).
  - `[ ]` Regression test: `import os, sys as system_module` → pastikan
    `system_module` resolve ke `sys`.

- `[ ]` **Fix 3: Parenthesized / multi-line import (Python)**
  - `[ ]` Tangani `from x import (\n a as b,\n c,\n)` — idealnya dengan membaca
    field AST langsung (lihat Fix 5) alih-alih menambal regex lagi.
  - `[ ]` Regression test: `from subprocess import (call as run_cmd,)` → `run_cmd(...)`
    harus resolve ke `subprocess.call`.

- `[ ]` **Fix 4: Bug `get_node_text` byte-offset fallback**
  - `[ ]` `karsasec/semantic/resolver.py::get_node_text` — ganti kondisi
    `byte_start > 0 or byte_end < len(source_bytes)` menjadi cek eksplisit
    `byte_end > byte_start` (atau tambahkan flag `has_position: bool` di `ASTNode`).
  - `[ ]` Regression test dengan node bertanda `byte_start=0, byte_end=0` (posisi belum
    di-set) → pastikan jatuh ke fallback line-based, bukan return string kosong.

- `[ ]` **Fix 5 (opsional tapi direkomendasikan): Mulai migrasi dari regex-atas-teks ke field AST**
  - `[ ]` Untuk Python minimal, ganti `_process_imports`/`_process_assignments` agar
    membaca node anak terstruktur (`module_name`, `alias`) dari hasil parser,
    bukan `re.match` ke `get_node_text()`. Regex tetap dipakai sebagai fallback untuk
    bahasa yang parsernya belum selengkap Python.
  - `[ ]` Dokumentasikan di README modul: bahasa mana yang pakai jalur AST-native vs
    fallback regex, supaya batas keandalan jelas bagi siapa pun yang menambah rule.

- `[ ]` **Verifikasi Akhir**
  - `[ ]` Full suite hijau dari clone bersih (`git clone` baru, bukan working dir lama).
  - `[ ]` Update laporan hasil test dengan jumlah test **riil** + link run CI, bukan
    angka manual dari satu mesin.

**Definition of Done:** semua fix di atas punya regression test, suite jalan hijau di
CI dari clone bersih, dan tidak ada lagi path/asumsi spesifik-mesin di kode/test.

---

## Sprint 5 -- Project Graph & Dataflow Foundation
**Durasi:** ~6 minggu · **Prasyarat:** Sprint 4B selesai · **Prioritas:** 🔴 Tinggi

> **Revisi v2:** digabung dari 4 sprint terpisah (Project Graph, Graph Query API,
> Graph Serialization, Dataflow Engine) menjadi satu sprint besar dengan 4 sub-fase.
> Alasan penggabungan: keempatnya membangun satu subsistem yang sama dan saling
> bergantung erat -- memecahnya jadi sprint independen menambah overhead koordinasi
> tanpa manfaat jelas untuk tim kecil. Urutan sub-fase di bawah tetap harus dijaga
> (tidak boleh dikerjakan paralel/acak) karena setiap fase adalah fondasi fase berikutnya.

Mengisi `karsasec/graph/` yang saat ini kosong. Tanpa ini, semantic resolver hanya
berguna dalam 1 file, dan rule masih terjebak pola *Symbol -> Regex* alih-alih
*Source -> Flow -> Sink* yang jauh lebih akurat.

- `[ ]` **5a. Skema & Builder (Project Graph)**
  - `[ ]` `karsasec/graph/node.py` -- `GraphNode` dengan metadata lengkap: `uuid`,
    `kind`, `language`, `qualified_name`, `namespace`, `signature`, `visibility`,
    `file`, `line`, `column` (bukan cuma `node_id` polos seperti draf awal).
  - `[ ]` `karsasec/graph/edge.py` -- `GraphEdge` dengan `caller`, `callee`, `type`
    (`CALLS`/`IMPORTS`/`DEFINES`/`INHERITS`), `confidence`, `location`, `resolved_by`
    (menandai apakah resolusi berasal dari AST-native, regex fallback, atau alias
    tracker -- penting untuk audit akurasi nanti).
  - `[ ]` `karsasec/graph/builder.py` -- agregasi seluruh `SemanticGraph` per-file
    hasil Sprint 4A/4B menjadi satu `ProjectGraph` lintas file.
- `[ ]` **5b. Graph Query API**
  - `[ ]` `karsasec/graph/query.py` -- antarmuka standar: `find_symbol()`,
    `find_calls()`, `find_definition()`, `find_reference()`, `reachable()`,
    `successors()`, `predecessors()`, `shortest_path()`.
  - `[ ]` Semua konsumen graph berikutnya (rule matcher, dataflow engine, nanti RAG/AI)
    **wajib** lewat API ini, bukan akses langsung ke struktur internal graph.
- `[ ]` **5c. Dataflow Engine**
  - `[ ]` `karsasec/graph/dataflow.py` -- `DataflowNode`/`DataflowEdge` untuk
    melacak Variable Flow, Assignment Flow, Parameter Flow, Return Flow
    (contoh: `user_input -> a -> b -> run() -> os.system()` harus bisa ditelusuri
    penuh, bukan cuma alias langsung seperti Sprint 4A).
  - `[ ]` Ini yang mengubah rule matching dari *Symbol -> Regex* menjadi
    *Source -> Flow -> Sink* -- dampaknya dirasakan langsung di Sprint 6.
- `[ ]` **5d. Serialization & Cache**
  - `[ ]` `karsasec/graph/serialize.py` -- simpan `ProjectGraph` ke SQLite (format
    utama) dengan opsi export JSON. Prioritas SQLite karena butuh query cepat &
    partial-read, bukan cuma dump/load penuh -- dan akan dipakai ulang oleh
    Enterprise Hardening (Sprint 10.5) untuk incremental scan.
- `[ ]` **Integrasi ke rule matcher**
  - `[ ]` Perluas `VisitorContext` (`karsasec/parser/ast/context.py`) agar bisa
    query `ProjectGraph` via Graph Query API.
  - `[ ]` `SymbolPredicate` (`karsasec/rules/matcher/predicates/symbol.py`) -- tambah
    langkah resolusi dataflow lintas file sebelum fallback regex.
- `[ ]` **Testing**
  - `[ ]` Proyek multi-file sintetis (≥3 file: `controller.py` -> `service.py` ->
    `repository.py`) memverifikasi input pengguna bisa ditelusuri sampai sink di
    file ketiga lewat Dataflow Engine, bukan cuma Query API kosong.

**Definition of Done:** taint bisa ditelusuri lintas ≥2 file untuk Python via
Source->Flow->Sink; Graph Query API dipakai oleh minimal 1 predicate rule matcher;
graph bisa di-serialize dan di-load ulang tanpa rebuild dari nol.

---

## Sprint 6 -- Rule Berkualitas Tinggi: Python & JavaScript
**Durasi:** ~3 minggu · **Prasyarat:** Sprint 5 (rule berbasis Dataflow butuh Query API) · **Prioritas:** 🟡 Sedang-Tinggi

> **Revisi v2:** prioritas diubah dari *jumlah rule* menjadi *precision per rule*.
> 10 rule dengan precision 95% lebih bernilai daripada 50 rule dengan precision 70% --
> rule berisik (banyak false-positive) justru merusak kepercayaan user terhadap tool.

- `[ ]` Audit gap: bandingkan rule yang ada vs OWASP Top 10 2021 + CWE Top 25,
  buat matriks cakupan (`docs/RULE_COVERAGE_MATRIX.md`).
- `[ ]` Tambah rule Python via Dataflow Engine (bukan regex simbol lagi): SSRF, XXE,
  Path Traversal, SSTI (Jinja2), Insecure Deserialization tambahan (pickle/yaml.load),
  Hardcoded Crypto Key, Insecure Random, Open Redirect, Broken Access Control pattern
  umum (Django/Flask).
- `[ ]` Tambah rule JavaScript/Node: SSRF (axios/node-fetch), Prototype Pollution,
  Path Traversal, ReDoS pattern umum, Insecure JWT (`alg: none`), NoSQL Injection
  (MongoDB), CORS misconfig, Open Redirect.
- `[ ]` Setiap rule baru wajib disertai corpus (`vulnerable/`, `safe/`, `regression/`)
  di `security_corpus/`.
- `[ ]` **Rule Benchmark Card per rule** -- setiap rule (baru maupun 10 rule lama)
  dapat skor tercatat: Precision, Recall, F1, Runtime, Memory, Corpus Size
  (`docs/RULE_COVERAGE_MATRIX.md` diperluas jadi mencatat ini, bukan cuma daftar
  cakupan on/off).
- `[ ]` Gate merge: rule baru **wajib** precision ≥ ambang yang disepakati tim
  (mis. ≥85%) sebelum digabung ke rule set produksi -- jumlah rule bukan lagi ukuran
  keberhasilan sprint ini.

**Definition of Done:** setiap rule (lama & baru) punya kartu skor precision/recall/F1
tercatat; Python & JS ≥80% OWASP Top 10 ter-cover dengan rule yang sudah lolos gate
precision (dicatat "N/A untuk SAST" untuk kategori yang memang butuh DAST).

---

## Sprint 7 -- Rule PHP & Go + Taint Lintas Fungsi
**Durasi:** ~3 minggu · **Prasyarat:** Sprint 6 (pola/template & gate precision sudah matang) · **Prioritas:** 🟡 Sedang

- `[ ]` Tambah rule PHP: LFI/RFI, Object Injection (`unserialize`), Laravel-specific
  raw query (`DB::raw`), Insecure File Upload -- dengan Rule Benchmark Card yang sama
  seperti Sprint 6.
- `[ ]` Tambah rule Go: SSRF, Path Traversal, Insecure TLS Config
  (`InsecureSkipVerify`), Command Injection variasi `exec.Command` dengan input
  tidak tersanitasi.
- `[ ]` Perluas Dataflow Engine (`karsasec/graph/dataflow.py`) agar mendukung
  pelacakan lintas **fungsi dalam file yang sama**, termasuk melalui parameter
  fungsi dan return value sederhana.

**Definition of Done:** 4 bahasa (Python/JS/PHP/Go) punya cakupan rule proporsional,
semua dengan kartu skor precision/recall; matriks cakupan di-update.

---

## Sprint 8 -- Software Composition Analysis (SCA)
**Durasi:** ~2-3 minggu · **Prasyarat:** independen, bisa paralel dengan Sprint 6/7 · **Prioritas:** 🟡 Sedang-Tinggi

Modul baru -- tidak ada kode SCA sama sekali di repo saat ini meski disebut di
spesifikasi arsitektur.

- `[ ]` Buat modul `karsasec/sca/` dengan struktur provider yang bisa diganti,
  **bukan hanya OSV API**:
  ```
  karsasec/sca/
  ├── providers/
  │   ├── osv.py        # Online, default
  │   ├── nvd.py         # Online, alternatif
  │   └── offline.py     # Offline database -- wajib untuk klien enterprise air-gapped
  ```
- `[ ]` Parser manifest: `package-lock.json`/`yarn.lock` (npm), `composer.lock`
  (PHP), `go.sum` (Go), `requirements.txt`/`poetry.lock` (Python).
- `[ ]` Deteksi dasar: dependency dengan CVE known, versi outdated jauh dari latest,
  lisensi berisiko (GPL di proyek closed-source, dsb.).
- `[ ]` CLI command baru: `karsasec sca scan` (`karsasec/cli/commands/sca.py`) --
  dengan flag `--provider offline` untuk mode air-gapped.
- `[ ]` Test dengan manifest sintetis berisi paket yang diketahui punya CVE publik.

**Definition of Done:** `karsasec sca scan <path>` menghasilkan daftar dependency
rentan dengan CVE ID, severity, versi perbaikan; bisa jalan tanpa akses internet
lewat provider offline.

---

## Sprint 9 -- IaC, Container & CI/CD Pipeline Security
**Durasi:** ~3 minggu · **Prasyarat:** independen, bisa paralel dengan Sprint 6/7/8 · **Prioritas:** 🟢 Sedang

> **Revisi v2:** cakupan diperluas dari "Docker & K8s saja" ke konfigurasi CI/CD,
> karena secret dan misconfig kerap bocor lewat file pipeline (`.github/workflows/`,
> `.gitlab-ci.yml`), bukan cuma Dockerfile.

- `[ ]` Buat modul `karsasec/iac/` (baru).
- `[ ]` Rule dasar Dockerfile: root user execution, unpinned base image, hardcoded
  secret di `ENV`/`ARG`, `--privileged` flag.
- `[ ]` Rule dasar Kubernetes manifest: `privileged: true`, `hostNetwork: true`,
  missing `resources.limits`, `runAsNonRoot` tidak di-set.
- `[ ]` Rule dasar CI/CD config: GitHub Actions, GitLab CI, Azure Pipelines, CircleCI
  -- fokus ke hardcoded secret, `pull_request_target` tanpa guard, third-party action
  tanpa pin versi/hash.
- `[ ]` CLI command baru: `karsasec iac scan`.

**Definition of Done:** scan terhadap Dockerfile/K8s manifest/CI config publik yang
memang punya misconfig dikenal menghasilkan temuan yang sesuai.

---

## Sprint 9.5 -- Dynamic Pipeline Optimization & DAG Orchestration
**Durasi:** ~2 minggu · **Prasyarat:** Sprint 8/9 · **Prioritas:** 🔴 Wajib sebelum AI Agent

Fase ini membangun Directed Acyclic Graph (DAG) Execution Planner & Dependency Scheduler non-AI.
Planner secara dinamis mengevaluasi deklarasi `requires` rule (`ast`, `semantic`, `dataflow`) sehingga pass analisis mahal (seperti dataflow/callgraph) hanya dipanggil secara *lazy* jika ada rule aktif yang membutuhkannya.

- `[ ]` **DAG Pipeline Planner Engine**: Membangun grafik dependen eksekusi untuk rule matcher.
- `[ ]` **Lazy Analysis Scheduler**: Melewati resolusi `semantic` / `dataflow` jika rule aktif set hanya membutuhkan `AST`.
- `[ ]` **Artifact & Node Caching**: Cache parsial untuk ASTNode dan temuan sementara antar pass.
- `[ ]` **Execution Telemetry & Benchmarking**: Pengukuran overhead latensi per pass dalam DAG.

**Definition of Done:** Engine secara otomatis melewati tahapan dataflow/callgraph untuk rule yang hanya membutuhkan AST, menghemat waktu scan hingga 40-60%.

---

## Sprint 9.7 -- Intermediate Representation (IR) & Stable Finding Identity
**Durasi:** ~2 minggu · **Prasyarat:** Sprint 9.5 · **Prioritas:** 🔴 Wajib untuk Stabilitas Output Enterprise

Fase ini menstandarkan representasi perantara (*Generic IR*) dan identitas temuan deterministik (*Stable Finding Identity*) untuk menjamin interoperabilitas lintas bahasa dan pengujian regresi CI/CD yang stabil.

- `[ ]` **Generic IR Abstraction**: Menyediakan abstraksi perantara untuk pohon AST multi-bahasa (Python, JS, Go, PHP).
- `[ ]` **Capability Dependency Graph (`CapabilityGraph`)**: Menyusun grafik dependensi teratur untuk topological sorting: `AST -> SEMANTIC -> TYPE_INFO -> CALLGRAPH -> DATAFLOW`.
- `[ ]` **Stable Finding Identity & Hash Fingerprinting**: Mengimplementasikan `compute_stable_finding_fingerprint` berbasis hash deterministik dari rule_id, file path ter-normalisasi, line, snippet, dan CWE.
- `[ ]` **Incremental Finding Diffing Engine**: Mendeteksi temuan `fixed`, `unchanged`, `moved`, dan `reopened` antar-run pada CI/CD pipeline.

**Definition of Done:** Setiap temuan memiliki hash identitas deterministik 32-karakter yang bertahan saat file dipindah atau diedit tanpa mengubah isi vulnerabilitas.

---

## Sprint 10 -- Benchmark Akurasi (Gerbang Wajib Sebelum AI)
**Durasi:** ~2 minggu · **Prasyarat:** Sprint 6-9 selesai · **Prioritas:** 🔴 Wajib sebelum Fase AI

> **Revisi v2:** sprint ini fokus **akurasi saja** (precision/recall/F1). Benchmark
> performance/memory/concurrency/scalability dipindah ke Sprint 10.5 karena secara
> alami satu paket dengan kerja caching & paralelisasi di sana -- memisahkannya di
> sini hanya akan diukur ulang setelah Sprint 10.5 mengubah arsitektur eksekusi.

- `[ ]` Perluas `security_corpus/` jadi representatif -- idealnya ambil sampel dari
  proyek open-source nyata yang sudah punya CVE terdokumentasi, bukan cuma snippet
  buatan sendiri.
- `[ ]` Agregasi seluruh Rule Benchmark Card (dari Sprint 6/7) jadi satu laporan
  akurasi keseluruhan per bahasa & per kategori kerentanan.
- `[ ]` Publikasikan hasil di `docs/BENCHMARK_RESULTS.md` -- termasuk angka yang
  jelek sekalipun, supaya jadi baseline jujur.
- `[ ]` Tetapkan gate resmi: rule baru ke depan tidak boleh diterima jika menurunkan
  precision keseluruhan di bawah ambang yang disepakati tim.

**Definition of Done:** ada laporan benchmark akurasi publik/internal yang jadi
baseline sebelum Fase AI -- supaya nanti bisa diukur objektif apakah AI benar-benar
meningkatkan akurasi atau justru menambah noise.

---

## Sprint 10.5 -- Enterprise Hardening (Performa & Cache)
**Durasi:** ~3-4 minggu · **Prasyarat:** Sprint 5 (butuh graph serialization) & Sprint 10 · **Prioritas:** 🟡 Sedang-Tinggi

AI akan mahal (biaya token + latensi). Sebelum LLM masuk ke pipeline, pastikan
mesin non-AI sudah efisien -- supaya biaya AI nanti tidak membengkak menutupi
inefisiensi yang sebenarnya bisa dihindari di layer bawah.

- `[ ]` **Incremental scan** -- pakai `ProjectGraph` yang sudah di-serialize (Sprint
  5d) untuk scan ulang hanya file yang berubah (diff-based), bukan full rescan.
- `[ ]` **AST & Graph cache** -- hindari re-parse file yang tidak berubah antar-run.
- `[ ]` **Parallel scan** -- worker pool untuk analisis multi-file (mulai dari desain
  sederhana; hindari premature-optimize ke arah memory pool custom sebelum ada
  bukti kebutuhan skala nyata).
- `[ ]` Benchmark performance/memory/concurrency (dipindah dari Sprint 10) diukur
  di sini, setelah caching & paralelisasi diterapkan -- supaya angkanya relevan
  dengan arsitektur final, bukan arsitektur lama yang belum di-cache.

**Definition of Done:** scan ulang proyek besar dengan sedikit perubahan file jauh
lebih cepat dari full-rescan; ada angka performance/memory/concurrency yang tercatat
sebagai baseline sebelum biaya AI ditambahkan.

---

## Sprint 11+ -- Fase AI/Agent (baru dibuka setelah Sprint 10.5)

> **Revisi v2 -- urutan dikoreksi.** Urutan di bawah memisahkan dua sumbu yang
> berbeda: (a) urutan **membangun kapabilitas** agen vs (b) urutan **eksekusi**
> agen saat runtime. Reflection/Validator dibangun **sebelum** Patch/Remediation
> secara kapabilitas, supaya begitu Patch agent mulai dipakai sungguhan, jaring
> pengamannya sudah ada dan teruji -- bukan ditambahkan belakangan setelah patch
> otomatis sudah sempat jalan tanpa pengawasan.

1. `[ ]` **RAG & Explainer** (AG-04 + kemampuan menjelaskan temuan) -- isi
   `karsasec/rag/`. Risiko rendah: murni baca & jelaskan, tidak mengubah apa pun.
2. `[ ]` **Root Cause Analysis** -- lapisan penjelasan lebih dalam di atas RAG,
   masih read-only.
3. `[ ]` **Reflection & Policy Validator** (AG-10/11) -- isi `karsasec/agents/`,
   fokus **mengurangi false-positive** dari mesin yang sudah ada. Ini harus siap
   dan teruji sebelum langkah 4.
4. `[ ]` **Discovery & DAG Planner** (AG-00/01) -- orkestrasi ringan untuk
   menjadwalkan agen-agen di atas.
5. `[ ]` **Remediation & Patch** (AG-09) -- generate patch, tapi **wajib** lewat
   Reflection/Validator (langkah 3) sebelum patch dianggap valid -- sesuai
   *Iterative Reflection & Re-Patch Loop* yang memang sudah didesain di
   `AGENT_SPECIFICATIONS.md`.
6. `[ ]` **Specialist Analysis agents penuh** (AG-05-08) -- lapisan LLM di atas
   rule engine untuk analisis yang butuh reasoning lebih dalam dari rule statis.
7. `[ ]` **Multi-Agent orchestration penuh** -- DAG planner lengkap dengan
   parallel execution & cost routing, setelah semua agen individual terbukti
   akurat satu-per-satu.

*(Detail task-level untuk Sprint 11+ akan disusun setelah Sprint 10/10.5 selesai dan
hasil benchmark diketahui -- menyusun task AI sebelum ada baseline akurasi & performa
berisiko salah prioritas.)*

---

## Ringkasan Timeline

| Sprint | Fokus | Durasi | Bisa Paralel? |
|---|---|---|---|
| 4B | Stabilisasi bug kritis | 2 minggu | Tidak -- blocker |
| 5 | Project Graph + Query API + Serialization + Dataflow | 6 minggu | Tidak -- setelah 4B |
| 6 | Rule berkualitas tinggi Python & JS | 3 minggu | Bisa mulai bareng Sprint 8/9 |
| 7 | Rule PHP & Go + taint lintas fungsi | 3 minggu | Setelah Sprint 6 |
| 8 | SCA (dgn provider offline) | 2-3 minggu | Paralel dgn 6/7 |
| 9 | IaC/Container/CI-CD | 3 minggu | Paralel dgn 6/7/8 |
| 10 | Benchmark akurasi | 2 minggu | Setelah 6-9 |
| 10.5 | Enterprise Hardening (cache, incremental, paralel) | 3-4 minggu | Setelah 5 & 10 |
| 11+ | AI/Agent (urutan dikoreksi di atas) | TBD | Setelah 10.5 |

**Total estimasi sampai siap masuk Fase AI: ±22-26 minggu** dengan 1-2 engineer.
Ini naik dari estimasi awal (14-16 minggu) setelah Sprint 5 diperluas mencakup
Dataflow Engine, dan Sprint 10.5 ditambahkan sebagai gerbang performa sebelum AI --
kenaikan ini nyata dan sengaja, bukan scope creep tanpa alasan: fondasi yang lebih
kuat di sini mengurangi risiko bongkar-pasang besar setelah Fase AI dimulai.

---

## Catatan Revisi (v1 -> v2)

Perubahan di dokumen ini dipicu oleh masukan eksternal yang direview ulang secara
kritis, bukan diadopsi mentah:

- **Diadopsi:** Dataflow Engine sebagai layer eksplisit, metadata graph yang lebih
  kaya, precision/recall per rule (bukan cuma jumlah rule), provider SCA offline,
  cakupan secret scanning ke CI/CD config.
- **Diadopsi dengan konsolidasi:** Graph Query API & Serialization digabung sebagai
  sub-fase Sprint 5, bukan sprint terpisah -- untuk tim kecil, memecahnya jadi 4
  sprint menambah overhead tanpa manfaat jelas.
- **Diadopsi dengan koreksi:** urutan Fase AI -- masukan asli menaruh Patch sebelum
  Reflection padahal argumennya sendiri menolak "Patch dulu". Urutan di dokumen ini
  menaruh Reflection/Validator sebelum Patch dibangun, bukan setelahnya.
- **Ditolak:** skor "9.8/10" untuk roadmap yang belum dieksekusi satu sprint pun --
  terlalu percaya diri untuk rencana di atas kertas; nilai sebenarnya baru diketahui
  setelah Sprint 4B-5 selesai dan estimasi diuji di dunia nyata.
