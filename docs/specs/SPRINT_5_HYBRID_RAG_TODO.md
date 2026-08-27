# Sprint 5 — Hybrid RAG Search Engine: TODO List

## Goal
Bangun subsystem retrieval hybrid untuk KarsaSec yang menggabungkan:
- lexical BM25 search
- static Model2Vec embeddings
- fusion ranking via Reciprocal Rank Fusion (RRF)

## Scope
- `karsasec/rag/`
- integrasi `Rule Engine` / `Analyzer`
- CLI option `--rag` / `--context-search`
- dokumentasi + test end-to-end

## Tasks

### 1. Core Engine
- [x] Buat `karsasec/rag/model2vec.py`
  - [x] implementasi static embedding berbasis token/code chunk
  - [x] dukungan CPU-only, tanpa cloud API
  - [x] unit tests untuk embedding konsistensi dan similarity

- [x] Buat `karsasec/rag/bm25.py`
  - [x] tokenisasi dan normalisasi dokumen kode
  - [x] implementasi scoring BM25
  - [x] indexing dokumen/corpus
  - [x] unit tests untuk ranking query sederhana

- [x] Buat `karsasec/rag/hybrid.py`
  - [x] integrasi hasil BM25 + Model2Vec
  - [x] implementasi Reciprocal Rank Fusion (RRF)
  - [x] API `retrieve(query: str, top_k: int)`
  - [x] unit tests untuk fusion ranking

### 2. Corpus & Indexer
- [x] Sediakan corpus internal kode dan dokumentasi keamanan
  - [x] rule snippets
  - [x] OWASP/CWE referensi
  - [x] sample vulnerable code patterns
- [x] Buat indexing pipeline corpus ke format pencarian cepat
  - [x] simpan teks chunk, metadata sumber, dan embedding
  - [x] pipeline rebuild dari file corpus bila diperlukan

### 3. Integrasi Engine
- [x] register komponen RAG di `karsasec/core/registry.py`
- [x] tambahkan interface/servis RAG di `karsasec/core/container.py`
- [ ] hubungkan RAG ke pipeline analyzer/rule engine
- [x] buat opsi CLI `karsasec scan --rag` atau `karsasec scan --context-search`
- [x] tambahkan opsi `--rag-rebuild` untuk memaksa rebuild index RAG lokal
- [x] pastikan `--rag` bisa menambahkan konteks relevan ke laporan

### 4. End-to-end Testing
- [x] Tambahkan tes end-to-end CLI untuk mode RAG
  - [x] verifikasi `karsasec scan --rag` mengembalikan context relevance
  - [x] pastikan output konsisten dan tidak menghasilkan error
- [x] Tambahkan unit tests untuk: 
  - [x] BM25 skor dasar
  - [x] Model2Vec similarity
  - [x] fusion ranking RRF

### 5. Dokumentasi
- [x] Update `docs/IMPLEMENTATION_ROADMAP.md` dengan detail status Sprint 5
- [x] Tambahkan penggunaan RAG di `README.md`
- [x] Buat contoh query + hasil retrieval pada `docs/SPRINT_5_HYBRID_RAG_TODO.md`

### 6. Performance & Validation
- [x] Benchmark latensi retrieval BM25 vs Model2Vec vs hybrid
- [x] Pastikan pipeline retrieval tetap cepat untuk korpus kecil-menengah
- [x] Dokumentasikan metrik performa sederhana

## Benchmark Notes
- Added `tests/benchmarks/test_rag_retrieval_benchmark.py`
- Validates retrieval speed for BM25, Model2Vec, and hybrid RAG on a synthetic security corpus
- Thresholds: BM25 < 0.5s, Model2Vec < 0.5s, Hybrid < 1.0s

## RAG Example
```bash
karsasec scan . --rag --rag-query "server-side request forgery"
```
- Menambahkan `rag_context` ke output JSON dan SARIF
- Menyimpan metadata source path dan skor rekues lokal
- Menambahkan dukungan `--rag-corpus` untuk menggunakan korpus eksternal lokal dari repositori publik atau dataset keamanan yang didownload

## Public Corpus Usage Example
```bash
# Clone a public security or code pattern corpus locally
# git clone https://github.com/OWASP/CheatSheetSeries.git /tmp/owasp-corpus
karsasec scan . --rag --rag-corpus /tmp/owasp-corpus --rag-query "server-side request forgery"
```
## Definition of Done
- [ ] Hybrid RAG engine terimplementasi dan terdaftar
- [ ] CLI `karsasec scan --rag` berfungsi
- [ ] Tes unit dan E2E hijau
- [ ] Dokumentasi Sprint 5 ditambahkan ke repo
- [ ] latensi retrieval dapat ditest dan didokumentasikan

### Sprint 5 Completion Notes
- [x] hubungkan RAG ke pipeline analyzer/rule engine
- [x] Hybrid RAG engine terimplementasi dan terdaftar
- [x] CLI `karsasec scan --rag` berfungsi
- [x] Tes unit dan E2E hijau
- [x] Dokumentasi Sprint 5 ditambahkan ke repo
- [x] latensi retrieval dapat ditest dan didokumentasikan

Sprint 5 is complete: the hybrid RAG retrieval is implemented, registered in the container, propagated into the analysis pipeline (`VisitorContext.rag_context`), and predicate support (`RAGPredicate`) is available for rules. Tests updated and added; see `tests/unit/rules/test_rag_context.py` and CLI tests.
