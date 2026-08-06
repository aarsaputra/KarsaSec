# KarsaSec v1.0 Roadmap (Enterprise Engine Architecture & Detection Engineering)

Platform: KarsaSec Secure Code Analysis Platform (SecOS)
Versi Roadmap: 1.6.0 (Shared Predicate Architecture & Enterprise Engine Focus) | Status: Milestone 1 Active - Capability & Quality Excellence
Visi Utama: "Menjadi platform Application Security Open Source terbaik (Setara Semgrep & CodeQL) dengan deterministic SAST/IaC engine yang presisi, framework-aware, dan terukur sebelum memasuki AI Layer."

---

## Strategic Roadmap Breakdown & Priority Schedule

| Prioritas | Modul / Fokus Utama | Target & Status Eksekusi |
|---|---|---|
| **P1** | **Shared Predicate Engine** | Compile-time predicate resolver (`karsasec/rules/predicates/`), YAML inheritance (`uses: predicate`), dependency validator, cycle detector (**COMPLETED**) |
| **P2** | **Rule Normalization** | Normalisasi metadata (CWE, OWASP, References, Remediation, Severity, Confidence) di seluruh rule (**COMPLETED**) |
| **P3** | **Rust Security Pack** | Axum, Actix-Web, Warp, Rust Native (15-20 Rules) memanfaatkan Shared Predicate Engine (**COMPLETED - 134 Rules Total**) |
| **P4** | **C# Security Pack Expansion** | ASP.NET Core: Razor XSS, ViewState, XXE, SSRF, File Upload, LDAP, XPath, Process.Start, Path Traversal, JWT (**NEXT**) |
| **P5** | **C++ Security Pack Expansion** | Format String, Double Free, Integer Overflow, Heap/Stack Overflow, Use After Free, Race Condition, `strcpy`, `gets`, `memcpy`, `sprintf` |
| **P6** | **HTML Security Pack** | Frontend security: CSP missing, sandbox iframe, `target="_blank"` rel, password autocomplete, inline script/style, mixed content |
| **P7** | **Multi-Cloud IaC Security Pack (110 Rules)** | Docker (15), Kubernetes (25), Terraform AWS (20), Azure (15), GCP (15), Helm (10), GitHub Actions (10) |
| **P8** | **Standalone Secret Detection Engine** | Pipeline terpisah: Regex → Entropy → Checksum → Context Validator → Confidence score (`karsasec/secrets/`) |
| **P9** | **Framework Intelligence & Manifest Scoring** | Deteksi otomatis `composer.json`, `package.json`, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle`, `requirements.txt`, `pyproject.toml`, `*.csproj` |
| **P10** | **Qualification Platform** | Evaluasi regresi otomatis terhadap OWASP Benchmark, Juliet, Juice Shop, NodeGoat, LaravelGoat, DVWA, WebGoat (`karsasec qualification`) |
| **P11** | **Dependency & SCA Engine** | Software Composition Analysis (SCA) parsing lockfiles (`package-lock.json`, `composer.lock`, `go.sum`, `Cargo.lock`) matching CVE/GHSA/OSV |
| **P12** | **AI Remediation & Advisory Layer** | Deterministic detection core terlebih dahulu, AI Layer untuk Explain Findings, Prioritizer, Fix Draft Generator, dan PR Security Copilot |

---

## Architecture Milestone Highlights

- **Shared Predicate Resolution (Compile-Time)**: Inhehitance predicate (`uses: predicate: <name>`) diselesaikan secara penuh pada tahap *YAML rule loading* (`YAMLRuleLoader`), memastikan zero runtime performance overhead, deterministic execution, dan validasi dini via `karsasec rules validate`.
- **Quality Gates**: Maintain Precision >= 95%, Recall >= 90%, FPR <= 5% terverifikasi via `tools/evaluate.py`.
