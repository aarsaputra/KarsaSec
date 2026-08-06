# KarsaSec v1.0 Roadmap (Detection Engineering & Quality Excellence)

Platform: KarsaSec Secure Code Analysis Platform (SecOS)
Versi Roadmap: 1.4.0 (Rule Quality Infrastructure & Multi-Language Pack Focus) | Status: Milestone 1 Active - Quality Excellence
Visi Utama: "Menjadi platform Application Security Open Source terbaik (Setara Semgrep & CodeQL) dengan deterministic SAST engine yang presisi, framework-aware, dan terukur sebelum memasuki AI Layer."

---

## Executive Overview & Sequential Execution Schedule

| Sprint | Fokus Utama | Target Status & Metrik Keberhasilan |
|---|---|---|
| **Sprint A3.0** | Rule Quality Infrastructure | Rule Validate, Lint, Docs Generator, Coverage Matrix CLI (**COMPLETED - 112 Rules**) |
| **Sprint A3.1** | PHP Security Pack (Laravel, Symfony, WP, Native) | 25+ Rules, Framework-Aware, Fixture Validation (**COMPLETED - 27 PHP Rules**) |
| **Sprint A4** | Go Security Pack (Gin, Echo, Fiber, stdlib) | 15-20 Rules, SSRF, SQLi, TLS, Command Injection, Secrets (**COMPLETED - 23 Go Rules**) |
| **Sprint A4.5** | Rule Quality Platform (Detection Engineering) | Rule Profiler, Conflict Detector, Dead Code Detector (**COMPLETED - 126 Rules Total**) |
| **Sprint A5** | Rust Security Pack (Axum, Actix, Warp) | 10-15 Rules, Unsafe memory, Command, SQL, Deserialization |
| **Sprint A6** | Lengkapi C#, C++, HTML Packs | Shared Predicate Engine, ASP.NET, C++ Memory/Format String, HTML CSP |
| **Sprint A7** | IaC Security Pack (Minimal 50 Rules) | Docker, Kubernetes, Terraform, Helm, GitHub Actions |
| **Sprint A8** | Secrets Detection Engine | Standalone engine with entropy + checksum (AWS, Azure, GCP, JWT, SSH, API Keys) |
| **Sprint A9** | Framework Intelligence & Dependency Targeting | Target resolution berdasarkan manifest (`composer.json`, `package.json`, `go.mod`) |
| **Sprint A10** | Benchmark & Qualification Platform | Benchmarking otomatis terhadap OWASP Benchmark, Juliet, DVWA, JuiceShop |
| **Milestone B** | DevEx & Enterprise Integration | CLI Doctor, SARIF Diff, HTML/PDF Reports, Quality Gate Policy |
| **Milestone C** | AI Layer (Explain, Prioritize, Fix Draft) | Explain Findings, Risk Prioritization, Fix Draft, PR Security Copilot |

---

# MILESTONE 1 - Detection Quality (Target: Setara Semgrep & CodeQL)

Prinsip: "Hasil pemindaian karsasec scan . harus memiliki nilai presisi tinggi (>=95%) dan terpercaya tanpa noise false positive berlebihan."

Target Kualitas Milestone 1:
- 120-150 High Quality Rules
- Precision >= 95.0%
- Recall >= 90.0%
- False Positive Rate (FPR) <= 5.0%

---

## Detail Sprint Breakdown

### Sprint A4 - Go Security Pack (COMPLETED)
- **Gin**: Raw SQLi (`c.Query` -> `db.Raw`), Unsanitized Command (`exec.Command`), SSRF (`http.Get`), Path Traversal (`c.File`), Open Redirect (`c.Redirect`).
- **Echo**: QueryParam SQLi (`c.QueryParam`), Inline HTML XSS (`c.HTML`), Hardcoded JWT Secret (`jwt.WithKey`).
- **Fiber**: Command Injection (`exec.Command`), Path Traversal (`c.SendFile`), Hardcoded Session Secret.
- **Go Stdlib**: Deprecated Crypto (`md5`, `sha1`), Unsafe Temp File (`os.CreateTemp("/tmp")`), Zip Slip (`archive/zip`).

### Sprint A4.5 - Rule Quality Platform (COMPLETED)
- **Modul `karsasec/quality/`**:
  - `CoverageAnalyzer`: Metrik cakupan per bahasa, CWE, OWASP, severity, framework.
  - `RuleProfiler`: Pengukuran latency evaluasi per rule (`karsasec rules profile`).
  - `ConflictDetector`: Deteksi nama duplikat & pattern regex overlap (`karsasec rules conflicts`).
  - `DeadCodeDetector`: Deteksi rule mati / klausa tidak lengkap (`karsasec rules dead-code`).
