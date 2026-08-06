# KarsaSec v1.0 Roadmap (Enterprise & Detection Engineering Standard)

Platform: KarsaSec Secure Code Analysis Platform (SecOS)
Versi Roadmap: 1.3.0 (Detection Engineering & Capability-First Roadmap) | Status: Milestone 1 Active - Detection Quality Focus
Visi Utama: "Menjadi platform Application Security Open Source terbaik (Setara Semgrep & CodeQL) dengan deterministic SAST engine yang presisi, framework-aware, dan terukur sebelum memasuki AI Layer."

---

## Executive Overview & Sequential Execution Schedule

| Sprint | Fokus Utama | Target Status & Metrik Keberhasilan |
|---|---|---|
| **Sprint A3.0** | Rule Quality Infrastructure | Rule Validate, Lint, Docs Generator, Coverage Matrix CLI (**COMPLETED - 112 Rules**) |
| **Sprint A3.1** | PHP Security Pack (Laravel, Symfony, WP, Native) | 25+ Rules, Framework-Aware, Fixture Validation (**COMPLETED - 27 PHP Rules**) |
| **Sprint A4** | Go Security Pack (Gin, Echo, Fiber, stdlib) | 15-20 Rules, SSRF, SQLi, TLS, Command Injection, Secrets |
| **Sprint A5** | Rust Security Pack (Axum, Actix, Warp) | 10-15 Rules, Unsafe memory, Command, SQL, Deserialization |
| **Sprint A6** | Lengkapi C#, C++, HTML Packs | ASP.NET Razor/XXE/ViewState, C++ Memory/Format String, HTML CSP/Sanitize |
| **Sprint A7** | IaC Security Pack (Minimal 30 Rules) | Docker, Kubernetes, Terraform, Helm, GitHub Actions |
| **Sprint A8** | Secrets Detection Engine | Engine khusus entropy & regex (AWS, Azure, GCP, JWT, SSH, API Keys) |
| **Sprint A9** | Framework Intelligence | Deteksi versi framework & library untuk rule targeting presisi tinggi |
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

### Sprint A3.0 - Rule Quality Infrastructure (COMPLETED)
- Sub-command CLI `karsasec rules`:
  - `validate`: Cek duplikat ID, CWE, OWASP, regex, remediasi, referensi eksternal.
  - `lint`: Format YAML, empty tags, deskripsi pendek.
  - `docs`: Generator Markdown otomatis di bawah `docs/rules/`.
  - `coverage`: Visualisasi cakupan rule per bahasa & kategori.
- Matriks Kompatibilitas `docs/RESEARCH_COMPATIBILITY_MATRIX.md`.

### Sprint A3.1 - PHP Security Pack + Framework Intelligence (COMPLETED)
- **Native PHP**: SQLi, Command Injection (`exec`, `shell_exec`, `passthru`), LDAP Injection, XPath Injection, NoSQL Injection, Phar Stream Deserialization, Zip Slip, Unrestricted Upload.
- **Laravel**: Raw Query (`DB::raw`, `whereRaw`), `APP_DEBUG=true`, Mass Assignment (`fill`, `create`), Unescaped Blade (`{!! !!}`).
- **WordPress**: `$wpdb->query` tanpa `prepare()`, Missing Nonce Verification (`wp_ajax`).
- **Symfony**: Expression Language Injection, Twig Unescaped Raw Output SSTI.

### Sprint A4 - Go Security Pack (Next)
- Frameworks: Gin, Echo, Fiber, stdlib.
- Coverage: Command Injection, SQLi, SSRF, TLS Misconfiguration, Secret Leaks, Path Traversal, Unsafe Pointer.

### Sprint A5 - Rust Security Pack
- Frameworks: Axum, Actix, Warp.
- Coverage: `unsafe` blocks, Command Injection, SQLi, Secret Leaks, Unsafe Deserialization.

### Sprint A6 - Lengkapi C#, C++, HTML Security Packs
- **C#**: ASP.NET XSS, CSRF, JWT, Path Traversal, ViewState, Razor Injection, XXE.
- **C++**: Double Free, Use After Free, Integer Overflow, Format String, `memcpy` Overflow, `new/delete` mismatch.
- **HTML**: CSP Missing, iframe sandbox, `target="_blank"`, mixed content, inline script, autocomplete password.

### Sprint A7 - IaC Security Pack
- Dockerfile, Kubernetes, Terraform, Helm, GitHub Actions (Minimal 30 Rules).

### Sprint A8 - Standalone Secrets Detection Engine
- Engine khusus dengan entropy calculation + regex validation untuk AWS, Azure, GCP, JWT, SSH, Slack, OpenAI, Anthropic, Gemini, Database URLs, Webhooks.

### Sprint A9 - Framework Intelligence & Execution Model
- Model dependency & manifest resolver (`composer.json`, `package.json`, `go.mod`, `Cargo.toml`, `requirements.txt`) untuk memfilter rule secara otomatis berdasarkan versi framework aktif.

### Sprint A10 - Qualification & Qualification Benchmark Platform
- Evaluasi otomatis terhadap OWASP Benchmark, Juliet Test Suite, DVWA, Juice Shop, Vulnerable Flask/Laravel Apps.
