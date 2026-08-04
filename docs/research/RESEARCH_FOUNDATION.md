# 🔬 KarsaSec — Research Foundation v1.0

**Judul:** Riset Arsitektur Sistem KarsaSec: Engine Keamanan Aplikasi Berbasis Agentic AI, Structural Code Graph, dan Integrasi SSDLC  
**Versi Dokumen:** 1.0 | **Terakhir Diperbarui:** 2026-08-04

> **Catatan Metodologi:** Dokumen ini merupakan fondasi riset arsitektur KarsaSec. Statistik dan metrik yang dikutip berasal dari penelitian industri dan akademik independen (ditandai `[Industry Research]`). Metrik performa spesifik KarsaSec akan ditetapkan secara terukur saat implementasi dan pengujian dilakukan.

---

1. Topologi Platform AI & Infra Abstraksi Multi-LLM
Arsitektur platform Artificial Intelligence (AI) pada KarsaSec didesain untuk menyediakan abstraksi terpadu terhadap beragam penyedia model bahasa besar (Large Language Models/LLMs) guna menjamin keandalan, efisiensi biaya, dan keamanan sistem secara penuh. Mengingat variabilitas antarmuka Application Programming Interface (API) serta ketidakpastian performa penyedia model komersial maupun sumber terbuka (open-source), KarsaSec mengadopsi pilar abstraksi middleware terpusat berbasis LiteLLM AI Gateway1.
Infrastruktur AI Gateway berada di antara lapisan klien KarsaSec (seperti CLI, Ekstensi IDE, dan Runner CI/CD) dan penyedia model fondasi eksternal. LiteLLM berfungsi sebagai lapisan gerbang terpadu yang memetakan format permintaan (request) dan tanggapan (response) dari standar OpenAI ke berbagai penyedia model seperti Anthropic, OpenAI, Google Gemini, hingga infrastruktur lokal berbasis vLLM atau Ollama1. Komponen gerbang ini mengisolasi logika internal KarsaSec dari perubahan skema API pihak ketiga1. Router dinamis mengatur alokasi kueri berdasarkan profil tugas Application Security (AppSec). Tugas dengan kebutuhan penalaran tinggi (high-reasoning tasks), seperti analisis alur data antarmodul dan sintesis patch perbaikan kerentanan, diteruskan ke model privat berskala besar seperti Claude 3.7 Sonnet atau GPT-4o2. Sebaliknya, tugas struktural berlatensi rendah (low-latency structural tasks), seperti ekstraksi entitas Abstract Syntax Tree (AST) dan klasifikasi sintaksis ringan, diteruskan ke model lokal terdistilasi seperti DeepSeek-Coder-V2 atau Qwen-2.5-Coder guna meminimalkan latensi dan biaya komputasi1.
KarsaSec mengimplementasikan skema ketahanan berjenjang (cascading failover). Apabila API utama mengalami pembatasan laju kueri (rate limit 429), kegagalan penyedia (5xx), atau latensi melampaui batas toleransi (SLA timeout), LiteLLM secara otomatis mengalihkan permintaan ke fallback model yang sepadan secara fungsional1. Eksekusi agen mandiri (autonomous agents) berisiko memicu perulangan tak terbatas (runaway retry loops) yang berpotensi menghabiskan anggaran komputasi secara masif6. Untuk mengatasi masalah ini, platform menerapkan Application-Aware Throttling dan pembatasan biaya berbasis batasan kueri (budget enforcement) per sesi audit6. Setiap tugas audit diberi token batas atas; jika konsumsi token melampaui ambang batas tanpa mencapai status terminal condition, eksekusi agen dihentikan secara otomatis6. Selain itu, sistem mengawasi urutan pemanggilan alat (tool call sequence), di mana pemanggilan alat yang identik berturut-turut lebih dari tiga kali memicu pembatalan eksekusi dan mengalihkan alur ke intervensi manusia atau penyederhanaan instruksi prompt4.
Ancaman utama pada sistem agen keamanan adalah serangan Prompt Injection tersembunyi di dalam kode sumber yang diaudit, yang ditemukan pada lebih dari 73% `[Industry Research: arXiv 2603.11088]` sistem agen produksi yang diuji3. KarsaSec mengintegrasikan lapisan proteksi berlapis (defense-in-depth guardrails) sebelum instruksi diproses oleh LLM3. Seluruh isi kode sumber yang diumpankan ke dalam konteks prompt diperlakukan sebagai untrusted data stream. Data ini diisolasi menggunakan delimiter terstruktur XML/JSON-RPC dan dibersihkan dari karakter kontrol serta pola instruksi tersembunyi (jailbreak patterns)3. Hasil sintesis LLM divalidasi secara komprehensif oleh komponen output validation guardrails eksternal sebelum dieksekusi oleh engine, memastikan agen tidak dapat memicu perintah shell berisiko tinggi tanpa verifikasi eksplisit2.
2. Benchmark AppSec & Metrik Evaluasi Sistem Agentic
Evaluasi agen AI pada domain AppSec memerlukan pendekatan yang berbeda dibanding evaluasi pembuatan kode umum (general code generation). KarsaSec memanfaatkan kombinasi benchmark mutakhir untuk mengukur ketepatan deteksi, kemampuan analisis kerentanan, dan tingkat keamanan tindakan agen2.
Benchmark SWE-bench dan SWE-agent mengukur kemampuan agen dalam menyelesaikan isu perangkat lunak riil pada repositori berbasis Python melalui interaksi lingkungan berbasis shell2. Sementara itu, SeCodePLT merupakan framework evaluasi risiko berbasis Common Weakness Enumeration (CWE) yang dirancang khusus untuk mengukur kepatuhan dan presisi deteksi kerentanan spesifik pada LLM dan agen kode2. Untuk mengevaluasi ketahanan terhadap ancaman keamanan agen itu sendiri, benchmark RedCode digunakan untuk menguji eksekusi kode berisiko tinggi dan kemampuan pembuatan program berbahaya, memverifikasi apakah agen dapat dimanipulasi untuk menghasilkan exploit eksploitatif atau memicu infectious jailbreak2.
Evaluasi agen pada KarsaSec menggunakan kerangka kerja dual-stage automated judges untuk memvalidasi output agen secara obyektif tanpa mengandalkan teks generatif semata2. Kerangka evaluasi ini dibagi menjadi dua kelompok penilai otomatis:
Robustness Judges (Evaluasi Keamanan):
Refusal Judge: Mengidentifikasi apakah agen berhasil menolak permintaan berbahaya (malicious prompt) dengan verifikasi predikat Yes/No/Unclear, di mana Compliance Rate mengukur persentase kepatuhan agen terhadap prompt2.
Attack Evaluation Judge: Menganalisis apakah hasil yang dihasilkan agen berdampak buruk (harmful) atau hanya sekadar templat edukatif. Output diklasifikasikan menjadi Good/Bad/Unclear, dan Attack Success Rate (ASR) dihitung berdasarkan proporsi output bertanda Bad2.
Executability Judges (Evaluasi Keandalan Kode):
Syntax-Error-Free Rate: Menggunakan parser Tree-sitter dan bytecode compiler untuk memverifikasi bahwa kode patch hasil perbaikan bebas dari kesalahan sintaksis2.
Runtime-Error-Free Rate: Menguji eksekusi program terperbaiki di dalam kontainer Docker terisolasi untuk memastikan kode berjalan hingga selesai dengan exit code 0 tanpa mengalami kegagalan runtime2.

Metrik / Benchmark
SWE-bench
SeCodePLT
RedCode
KarsaSec Benchmark Standard
Fokus Utama
Resolusi bug & fitur umum
Cakupan kerentanan CWE
Keamanan eksekusi & eksploitasi
Keamanan kode & Remediasi presisi
Metode Verifikasi
Unit Test Suites Pass/Fail
Static CWE Coverage Matching
Sandbox Execution & Jailbreak Rate
Dual-Stage (Robustness & Executability)2
Target Evaluasi
Agentic Tool-use (Bash/Git)
Code LLM Security Alignment
Multi-agent Safety Boundaries
Multi-agent MCP + AST Integrity7
Primary Metric
Resolve Rate (%)
CWE Precision/Recall (%)
Attack Success Rate (ASR %)2
Syntax & Runtime Error-Free Rate2

3. Arsitektur AI Agent & Protocol Standardization (MCP)
KarsaSec mengadopsi arsitektur kolaborasi multi-agen (multi-agent collaboration) berbasis spesialisasi peran, menggantikan pendekatan agen monolitik. Komunikasi antar-agen dan interaksi dengan lingkungan lokal distandarisasi menggunakan Model Context Protocol (MCP)3.
Sistem KarsaSec terbagi menjadi empat agen terspesialisasi yang beroperasi dalam sebuah state machine teratur. Orchestrator Agent bertindak sebagai pengendali utama yang menerima tugas, membagi pekerjaan, dan mengoordinasikan alur kerja. Static Auditor Agent berinteraksi dengan alat analisis statis dan knowledge graph untuk mengekstraksi jalur alur data (dataflow path) serta menemukan titik rentan. Dynamic Remediation Agent merancang perbaikan kode (remediation patch) berdasarkan aturan AppSec dan konteks arsitektur repositori. Selanjutnya, Verification Agent menguji perbaikan kode di dalam lingkungan terisolasi (sandbox) untuk memverifikasi bahwa kerentanan berhasil ditutup tanpa merusak fungsionalitas aplikasi.
Model Context Protocol (MCP) menyediakan antarmuka terstandardisasi berbasis JSON-RPC yang menghubungkan LLM dengan pustaka alat (toolkits), data eksternal, dan fungsi sistem3. Dalam KarsaSec, server MCP mengekspos fungsi analisis seperti pencarian pola AST, traversal graf ketergantungan, dan pemeriksaan status build7. Namun demikian, protokol MCP standar memiliki celah keamanan mendasar: server MCP menyatakan skema input/output tetapi tidak mendeklarasikan batasan kapabilitas runtime secara otomatis, sehingga server yang mengklaim hanya "membaca file" berpotensi dieksploitasi untuk menjalankan perintah shell arbitrer9.
Untuk menutup celah keamanan MCP tersebut9, KarsaSec membangun Capability-Constrained MCP Sandbox7. Setiap server MCP wajib mendeklarasikan manifes kapabilitas eksplisit, seperti Read-Only Filesystem, No Network Egress, atau AST Parse Only7. Seluruh proses instansiasi alat dieksekusi di bawah pengawasan kernel menggunakan eBPF atau strace untuk melarang panggilan sistem berbahaya seperti execve, fork, atau pembuatan koneksi jaringan di luar localhost7. Selain itu, akses file dibatasi secara ketat hanya pada direktori kerja repositori aktif, di mana upaya melakukan traversal direktori (../) atau mengakses jalur sensitif seperti ~/.ssh atau ~/.aws akan memicu penghentian sesi seketika7.
4. RAG Spesifik AppSec & Structural Codebase Knowledge Graph
Penerapan Retrieval-Augmented Generation (RAG) berbasis pencarian teks vektor konvensional pada kode sumber terbukti tidak efektif. Kode merupakan struktur relasional yang terikat oleh aturan sintaksis dan hirarki eksekusi; pemotongan teks secara acak (chunking by character/token count) merusak konteks fungsi dan menghasilkan hallucination pada analisis ketergantungan10. KarsaSec menggantikan RAG teks konvensional dengan Structural Codebase Knowledge Graph berbasis Tree-sitter dan SQLite7.
Alur pemrosesan kode dimulai ketika kode sumber mentah diparse oleh engine Tree-sitter multi-bahasa yang dikompilasi secara native dalam bahasa C/Rust7. Parser ini mengekstraksi entitas AST seperti definisi fungsi, kelas, lokasi pemanggilan, dan deklarasi impor lintas 66+ bahasa pemrograman7. Dibandingkan pemotongan teks biasa, AST-based semantic chunking memotong kode tepat pada batas deklarasi sintaktis (fungsi, metode, kelas, antarmuka)12. Hal ini menjamin bahwa setiap blok kode yang dimasukkan ke dalam konteks LLM memiliki kelengkapan struktur (syntactic integrity)7. Entitas yang diekstraksi kemudian disimpan secara permanen di dalam basis data SQLite lokal yang membentuk Codebase-Memory graph7.
KarsaSec memanfaatkan mesin pencari hibrida untuk menggabungkan pencarian leksikal presisi tinggi dengan pencarian semantik berbiaya murah5. Pencarian BM25 digunakan untuk menemukan nama variabel, pengenal fungsi (identifiers), dan kunci konfigurasi spesifik5. Sejalan dengan itu, model embedding statis ultra-ringan Model2Vec (seperti potion-code-16M) berjalan langsung di CPU tanpa memerlukan GPU atau panggilan API eksternal, memangkas latensi inferensi embedding hingga mendekati 0 ms5. Hasil dari kedua metode tersebut digabungkan menggunakan algoritma Reciprocal Rank Fusion (RRF) dengan formulasi matematika sebagai berikut:

Dalam persamaan ini,  mewakili himpunan metode pencarian (BM25 dan Model2Vec),  adalah posisi peringkat dokumen  pada metode , dan  adalah konstanta perataan (default ). Hasil gabungan ini kemudian ditingkatkan posisinya (reranked) berdasarkan bobot keterhubungan simbol AST5.
Infrastruktur Codebase-Memory KarsaSec menyimpan seluruh representasi AST, peta impor (import maps), alur pemanggilan (call-graphs), dan struktur komunitas relasional (dihitung via algoritma Louvain Community Detection) di dalam satu file basis data SQLite tunggal7. Pendekatan ini mendukung kueri analitis AppSec secara deterministik, seperti Reverse Impact Analysis untuk memetakan dampak perubahan modul dan Call Graph Path Tracing untuk melacak alur variabel dari titik masukan pengguna (source) hingga titik eksekusi rentan (sink) tanpa perlu membaca seluruh file secara terulang7.

Karakteristik
Naive Text Vector RAG
KarsaSec Structural Graph (Codebase-Memory)
Batas Pemotongan (Chunking)
Ukuran token tetap (misal: 512 token)
Sintaktis AST (Fungsi/Kelas penuh)12
Penyimpanan State
Vector Database Terpisah
Single SQLite File (Lokal/Zero Infra)7
Konsumsi Token Prompt
Tinggi (Memuat banyak chunk irrelevan)
Sangat Hemat (Memuat hanya simbol & graf terikat)5
Analisis Transitif (Impact)
Gagal / Terjadi Hallucination
Tepat melalui Call-Graph Traversal7
Kecepatan Indexing
Lambat (Terhambat forward pass LLM)
Sangat Cepat (~150ms/22 `[Industry Research: arXiv 2603.27277]` file `[Industry Research: arXiv 2603.27277]` via C/Rust Engine)5

5. Integrasi Seamless Software Security Development Lifecycle (SSDLC)
KarsaSec dirancang untuk menyatu secara otomatis ke dalam seluruh tahapan siklus hidup pengembangan perangkat lunak aman (Secure Software Development Life Cycle / SSDLC) tanpa mengganggu produktivitas pengembang (zero developer friction).
Pada tahap awal pembuatan kode (Shift-Left), KarsaSec menyediakan plugin IDE (VS Code / Cursor) dan perkakas baris perintah (native CLI). Menggunakan arsitektur kompilasi biner statis tunggal, CLI dapat menjalankan audit kilat pra-komit (pre-commit check) secara offline5. Pengembang menerima umpan balik langsung mengenai risiko kerentanan pada fungsi yang sedang ditulis sebelum kode tersebut diunggah ke repositori pusat4.
Di dalam lingkungan Continuous Integration/Continuous Deployment (CI/CD) seperti GitHub Actions atau GitLab CI, KarsaSec bertindak sebagai pengawas keamanan otomatis13. Untuk mencegah kegagalan pipeline yang tidak perlu (build friction), KarsaSec mengimplementasikan kebijakan progressive security gating. Kerentanan berdampak rendah hingga menengah dimunculkan sebagai anotasi peringatan pada log CI tanpa menghentikan proses build13. Sebaliknya, pipeline dihentikan secara otomatis (strict blocking) hanya jika ditemukan kerentanan berisiko tinggi (High/Critical) yang terverifikasi memiliki jalur eksploitasi aktif (exploitability path) dan skor EPSS melampaui ambang batas toleransi organisasi14. Selain itu, platform memanfaatkan modul kompresi log untuk memangkas ukuran log error CI hingga 98.9% `[Industry Research: arXiv 2603.27277]` sebelum dikirim ke konteks LLM, menghemat konsumsi token secara drastis5.
Ketika Pull Request (PR) atau Merge Request (MR) dibuat, agen KarsaSec secara otomatis melakukan audit terhadap selisih kode (git diff)10. Agen memetakan perubahan kode ke dalam Codebase-Memory graph untuk mengidentifikasi dampak perubahan terhadap modul lain7. Jika kerentanan baru terdeteksi, agen tidak hanya memberikan saran generatif, tetapi menyusun Inline Suggestion Patch secara presisi langsung pada baris kode yang terdampak di antarmuka PR13. Setiap patch dilengkapi dengan tes unit (remediation testcase) otomatis untuk membuktikan bahwa perbaikan tersebut menutup kerentanan tanpa merusak fungsionalitas aplikasi yang ada2.
6. State-of-the-Art AI Software Engineering & Closed-Loop Feedback
Arsitektur rekayasa perangkat lunak berteknologi AI pada KarsaSec mengadopsi pola ReAct (Reasoning and Acting) dan skema umpan balik tertutup (closed-loop feedback systems) untuk meminimalisasi kesalahan perbaikan kode13.
Agen KarsaSec beroperasi dalam iterasi ReAct yang teratur, mencakup pemikiran (Thought) untuk menganalisis temuan kerentanan dan struktur AST terkait, tindakan (Action) untuk memanggil alat spesifik melalui protokol MCP (seperti get_call_graph, read_symbol_definition, atau run_static_analysis), serta pengamatan (Observation) untuk memperbarui status pemahaman (internal state)7. Seluruh alur ini dibungkus di dalam Code-as-Agent Harness yang membatasi jumlah langkah eksekusi agar tidak terjadi perulangan tanpa batas6.
Membuat perbaikan kode keamanan (security patching) hanya berdasarkan inferensi LLM dalam satu kali jalan (single-shot generation) sering kali menghasilkan kesalahan sintaksis atau kegagalan kompilasi. KarsaSec menerapkan arsitektur LLMLOOP yang menghubungkan generatif AI dengan alat verifikasi statis deterministik13. Dalam alur iteratif ini:
Draft Generation: Agen perbaikan menghasilkan draf perbaikan kode berdasarkan konteks kerentanan.
Static Check & Compilation: Kode draf langsung diuji oleh parser Tree-sitter dan alat penganalisis statis (seperti py_compile, tsc, atau cargo check)2.
Diagnostic Feedback: Jika ditemukan kesalahan sintaksis atau tipe data, pesan error dari compiler ditangkap dan diumpankan kembali ke konteks LLM sebagai umpan balik korektif13.
Iterative Refinement: Agen memperbaiki draf kode berdasarkan pesan error tersebut secara berulang hingga kode lolos uji kompilasi secara sempurna13.
Setelah patch lolos pengujian statis, kode dieksekusi di dalam kontainer Docker terisolasi untuk pengujian dinamis (Runtime-Error Judge)2. Jika pengujian unit dan pengujian verifikasi keamanan berhasil dengan kode keluar 0 (exit code 0), patch diklasifikasikan sebagai Verified Self-Healing Patch dan siap untuk disetujui oleh pengembang2.
7. Arsitektur CLI Native & Plugin Ecosystem
Engine utama KarsaSec dirancang untuk berjalan secara efisien di lingkungan lokal pengembang maupun runner CI/CD yang terbatas komputasinya.
Mengikuti pola arsitektur perkakas modern seperti synaptic dan semble_rs, core engine CLI KarsaSec ditulis menggunakan bahasa pemrograman Rust dan dikompilasi menjadi satu biner statis mandiri (single static binary)5. Biner statis ini tidak membutuhkan runtime Python, Node.js, daemon tambahan, atau dependensi pustaka luar, sehingga menghasilkan waktu startup ultra-cepat dan konsumsi memori yang sangat kecil5. Seluruh fungsionalitas pemetaan AST, pencarian hybrid BM25/Model2Vec, dan pencarian graf berjalan secara offline di mesin lokal, di mana koneksi jaringan hanya digunakan saat melakukan panggilan inferensi ke LLM gateway5.
Untuk memperluas kapabilitas agen, KarsaSec mendukung Plugin & Skill Ecosystem berbasis standar MCP7. Namun, karena repositori skill pihak ketiga kerap membawa risiko keamanan (seperti model kepercayaan tanpa verifikasi pada OpenClaw atau Anthropic Skills)9, KarsaSec menerapkan mekanisme isolasi ketat:
Static Allow-List Audit: Panggilan pustaka fungsi berbahaya di dalam kode plugin diisolasi dan diwajibkan melewati daftar izin (allow-list) tertulis7.
Binary String & Payload Audit: Biner plugin dipindai secara otomatis untuk memdeteksi hardcoded credentials, URL mencurigakan, atau muatan terenkode Base64 yang tak terverifikasi7.
Egress Network Monitoring: Seluruh koneksi jaringan outbound dari plugin dipantau dan dibatasi secara ketat hanya ke domain yang diizinkan (whitelisted domains)7.
8. Rule Engine Deterministik & Lifecycle Penemuan Kerentanan (Finding Lifecycle)
KarsaSec menyeimbangkan kecepatan aturan deterministik dengan kecerdasan kontekstual LLM untuk menghasilkan sistem deteksi kerentanan dengan tingkat positif palsu (false positive) mendekati nol.
Proses deteksi dijalankan melalui arsitektur dua tahap (hybrid detection architecture). Pada Stage 1, engine pencocokan pola aturan berbasis AST memindai kode sumber untuk menemukan kandidat kerentanan secara instan. Pada Stage 2, agen Static Auditor menerima kandidat temuan, memuat Codebase-Memory graph, dan memverifikasi alur data (dataflow path) dari source ke sink7. Jika agen menemukan adanya fungsi sanitasi atau validasi di tengah jalur eksekusi, temuan otomatis ditandai sebagai False Positive dan ditapis dari laporan akhir.
Penilaian prioritas kerentanan tidak hanya mengandalkan keparahan teoretis, melainkan menggabungkan tiga indikator keamanan utama: CVSS v4.0 untuk keparahan teknis14, EPSS untuk estimasi probabilitas eksploitasi di alam liar dalam 30 hari ke depan14, serta CISA KEV untuk mengonfirmasi bukti eksploitasi aktif15. Skor Prioritas KarsaSec () dihitung menggunakan persamaan terbobot:

Di mana  jika CVE tercantum dalam katalog CISA KEV, dan  jika tidak ada15.
Untuk mencegah pemicuan alur kerja ganda atas masalah yang sama, KarsaSec menerapkan AST Node Hashing. Temuan kerentanan diidentifikasi berdasarkan sidik jari (fingerprint) dari jalur alur kontrol AST, bukan berdasarkan nomor baris kode yang dapat berubah saat refactoring. Setiap temuan dikelola melalui Finding State Machine yang mencakup lima status utama: New (kandidat awal dari pencocokan aturan AST), Triaged (terkonfirmasi jalur alur datanya oleh agen), Verified (terkonfirmasi rentan tanpa sanitasi dan diberi skor risiko), False Positive (dibatalkan karena adanya fungsi sanitasi valid), dan Remediated (patch perbaikan berhasil diverifikasi oleh Runtime Judge)2.

Status Finding
Kriteria Engine Deterministik
Konfirmasi Agent AI
Aksinya pada Pipeline SSDLC
New
Pola AST cocok dengan aturan SAST
Belum divalidasi
Dicatat dalam basis data audit sementara
Triaged
Kandidat kerentanan terkonfirmasi
Agent memverifikasi keberadaan jalur alur data
Penilaian prioritas skor CVSS/EPSS/KEV14
Verified
Alur Data dari Source ke Sink Valid
Agent memverifikasi tidak ada fungsi sanitasi
Pemicuan pembuatan PR Remediasi & CI Gate Blocking13
False Positive
Transaksi AST terdeteksi aman
Agent menemukan pemanggil ter-sanitasi
Temuan diabaikan, aturan disesuaikan
Remediated
Patch perbaikan diterbitkan
Runtime Judge konfirmasi Exit Code 0 & test pass2
PR di-merge, status kerentanan ditutup

9. Architecture Decision Records (ADRs)
ADR-001: Implementasi LiteLLM Gateway sebagai Middleware Abstraksi Model AI
Status: Approved
Context: KarsaSec membutuhkan kemampuan untuk memanfaatkan berbagai provider LLM (Anthropic, OpenAI, Model Lokal) tanpa membebani logika aplikasi dengan antarmuka API yang berbeda-beda. Selain itu, eksekusi agen berpotensi memicu biaya tak terkendali akibat perulangan panggilan API (runaway loops)1.
Decision: Mengadopsi LiteLLM AI Gateway sebagai middleware terpusat untuk seluruh permintaan inferensi LLM1. LiteLLM mengelola dynamic routing, fallback strategy, pembatasan anggaran token per sesi audit, serta application-aware throttling1.
Consequences: Mengisolasi kode utama dari perubahan API vendor dan memangkas risiko pembengkakan biaya cloud melalui failover otomatis1. Namun, pendekatan ini menambahkan satu titik komputasi (hop) middleware yang menambah latensi overhead minimal (~5-10ms).
ADR-002: Adopsi Tree-Sitter AST & SQLite-based Codebase-Memory untuk Graph RAG
Status: Approved
Context: RAG berbasis pencarian teks vektor konvensional gagal memetakan keterhubungan relasional pada kode sumber, menghasilkan token cost yang sangat tinggi dan tingkat hallucination yang tidak dapat diterima pada tugas AppSec10.
Decision: Membangun Codebase-Memory graph memanfaatkan parser multi-bahasa Tree-sitter dan penyimpan relasional SQLite lokal7. Pencarian menggabungkan teknik BM25 leksikal dan Model2Vec embedding statis via Reciprocal Rank Fusion (RRF)5.
Consequences: Penghematan konsumsi token hingga 10x lipat `[Industry Research: arXiv 2603.27277]`, serta analisis transitif alur data (call-graph) dan dampak perubahan (impact analysis) menjadi 100% deterministik7. Namun, metode ini membutuhkan tahap indeksasi awal (indexing overhead) saat repositori pertama kali dibuka7.
ADR-003: Standarisasi Integrasi Tool Berbasis Model Context Protocol (MCP) dengan Sandbox Capability
Status: Approved
Context: KarsaSec memerlukan antarmuka terstandar untuk menghubungkan AI Agent dengan perkakas analisis keamanan dan eksekusi lokal3. Namun, spesifikasi MCP standar tidak memiliki mekanisme pembatasan kapabilitas runtime yang aman9.
Decision: Mengadopsi protokol MCP (Model Context Protocol) untuk integrasi seluruh alat agen, disempurnakan dengan Capability Sandbox Enforcement Layer7. Sandbox mengisolasi eksekusi alat menggunakan pembatasan akses sistem (eBPF/strace filtering) dan kontrol direktori kerja ketat7.
Consequences: Memungkinkan ekosistem alat yang modular dan terstandar sambil menjaga agen dari ancaman eksekusi kode berbahaya atau eksfiltrasi data3. Namun, pengoperasian server MCP memerlukan verifikasi manifes keamanan tambahan sebelum dapat dijalankan.
ADR-004: Strategi Bahasa Inti — Python-First, Rust-Accelerated
Status: Approved (Diperbarui 2026-08-04)
Context: KarsaSec membutuhkan kecepatan delivery MVP yang tinggi sekaligus performa eksekusi CLI yang baik. Rust murni dari awal meningkatkan risiko delivery dan kompleksitas hiring. Sebaliknya, Python murni berpotensi menjadi bottleneck pada parsing AST skala besar.
Decision: Mengadopsi strategi **Python-First, Rust-Accelerated**:
- **Phase 1–2 (MVP):** Seluruh orkestrasi, agen, RAG, Memory Layer, dan Plugin API ditulis Python 3.11+ (`typer`, `pydantic`, `litellm`, `tree-sitter` Python bindings).
- **Phase 3+ (Acceleration):** Komponen hot-path yang terbukti menjadi bottleneck secara empiris (parser AST, traversal knowledge graph skala besar) dimigrasikan ke Rust sebagai ekstensi biner statis dengan `pyo3` bindings.
Consequences: Kecepatan iterasi MVP tinggi dengan Python. Single static binary Rust menjadi target akhir Phase 4+, bukan prasyarat Phase 1. Trade-off: latensi awal CLI lebih tinggi dibanding Rust pure, namun dapat diterima untuk MVP.
ADR-005: Algoritma Prioritisasi Risk Multi-Dimensional Menggunakan CVSS v4.0, EPSS, dan KEV
Status: Approved
Context: Menilai kerentanan hanya berdasarkan skor dasar CVSS memicu alert fatigue karena banyaknya temuan berisiko teoritis yang tidak pernah dieksploitasi secara nyata14.
Decision: Mengimplementasikan algoritma penilaian risiko terintegrasi yang menggabungkan skor CVSS v4.0, estimasi probabilitas eksploitasi EPSS, dan kehadiran dalam katalog CISA KEV14.
Consequences: Tim pengembang dapat memprioritaskan perbaikan pada kerentanan yang paling berdampak dan sedang dieksploitasi secara aktif di alam liar14. Namun, sistem membutuhkan pembaruan umpan data (data feed) EPSS dan KEV secara berkala melalui koneksi internet.

10. Research Limitations & Disclaimer

Dokumen riset ini menetapkan fondasi arsitektur berdasarkan penelitian industri terkini. Beberapa poin penting untuk dipahami:

**Klaim Riset Industri vs. Target KarsaSec:**
- Statistik bertanda `[Industry Research]` bersumber dari paper akademis/industri independen, bukan pengukuran langsung sistem KarsaSec
- Target performa KarsaSec (latensi, akurasi, token efficiency) akan ditetapkan melalui benchmark internal selama Phase 1-2
- Klaim seperti "penghematan token 10x" dan "150ms indexing" merupakan referensi baseline dari riset Tree-sitter/Codebase-Memory, bukan garansi performa produksi

**Scope Riset:**
- Riset ini mencakup arsitektur platform per Agustus 2026
- Ekosistem LLM dan tool keamanan berubah cepat; `provider_routes.yaml` dan `tool_registry.yaml` harus diperbarui secara berkala
- ADR (Architecture Decision Records) di §9 merupakan keputusan yang dapat direvisi berdasarkan temuan empiris selama implementasi

**Referensi Akademis:**
Seluruh klaim riset dapat ditelusuri melalui daftar referensi di bagian akhir dokumen. Nomor superscript (1–15) merujuk pada sumber yang terdaftar.


Kesimpulan
Riset arsitektur sistem KarsaSec ini menunjukkan transformasi paradigma analisis keamanan aplikasi dari metode pencarian teks generatif konvensional menuju pendekatan terintegrasi yang menggabungkan kepastian deterministik Structural Code Graph dan kecerdasan adaptif Agentic AI3. Melalui implementasi middleware LiteLLM Gateway, KarsaSec menjamin keandalan dan efisiensi biaya inferensi1, sementara mitigasi kerentanan pada Model Context Protocol (MCP) dicapai melalui kontrol kapabilitas sandbox berakses terbatas di tingkat kernel7. Penggunaan parser Tree-sitter dan Codebase-Memory berbasis SQLite memangkas konsumsi token hingga 10x lipat dan menghilangkan hallucination pada penelusuran alur data kerentanan7. Dipadukan dengan siklus umpan balik tertutup (LLMLOOP)13, engine CLI berbasis Rust5, serta penilaian prioritas berdasar kombinasi CVSS v4.0, EPSS, dan KEV14, KarsaSec menyajikan fondasi arsitektur AppSec modern yang aman, presisi, dan siap diimplementasikan secara lancar di seluruh rantai SSDLC enterprise.
Karya yang dikutip
A Unified Agent Control Plane - LiteLLM, https://docs.litellm.ai/blog/agents-are-the-new-llms
Security Assessment of AI Code Agents Through Systematic Jailbreaking Attacks - arXiv, https://arxiv.org/html/2510.01359v2
The Attack and Defense Landscape of Agentic AI: A Comprehensive Survey - arXiv, https://arxiv.org/html/2603.11088v1
SWE-chat: Coding Agent Interactions From Real Users in the Wild - arXiv, https://arxiv.org/html/2604.20779v1
semble_rs - AI Agents on GitHub | SkillsLLM - AI Skills Marketplace, https://skillsllm.com/skill/semble-rs
Security for Production AI Agents in 2026 - Iain Harper's Blog, https://iain.so/security-for-production-ai-agents-in-2026
Codebase-Memory: Tree-Sitter-Based Knowledge Graphs for LLM Code Exploration via MCP - arXiv, https://arxiv.org/html/2603.27277v1
Formal Security Analysis of Agent Protocol Composition - arXiv, https://arxiv.org/html/2606.28690
Formal Analysis and Supply Chain Security for Agentic AI Skills - arXiv, https://arxiv.org/html/2603.00195v1
Code Graph MCP Server, https://mcpservers.org/servers/colinvaughn/codegraph
Codebase-Memory: Tree-Sitter-Based Knowledge Graphs for LLM Code Exploration via MCP - arXiv, https://arxiv.org/pdf/2603.27277
How AI Knowledge Graphs Turn Legacy Code into Structured Intelligence - SoftwareSeni, https://www.softwareseni.com/how-ai-knowledge-graphs-turn-legacy-code-into-structured-intelligence/
YennNing/Awesome-Code-as-Agent-Harness-Papers - GitHub, https://github.com/YennNing/Awesome-Code-as-Agent-Harness-Papers
Common Vulnerability Scoring System - Wikipedia, https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System
NIST CVE Prioritization as AI Speeds Up Vulnerability Discovery - Penligent, https://www.penligent.ai/hackinglabs/nist-cve-prioritization-as-ai-speeds-up-vulnerability-discovery/
An Exploratory Study of Code Retrieval Techniques in Coding Agents - Preprints.org, https://www.preprints.org/manuscript/202510.0924