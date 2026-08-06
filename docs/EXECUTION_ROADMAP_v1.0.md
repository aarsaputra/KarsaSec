# KarsaSec v1.0 Roadmap (Detection Engineering & Multi-Cloud Excellence)

Platform: KarsaSec Secure Code Analysis Platform (SecOS)
Versi Roadmap: 1.5.0 (Shared Predicate Architecture & Multi-Cloud IaC Focus) | Status: Milestone 1 Active - Quality Excellence
Visi Utama: "Menjadi platform Application Security Open Source terbaik (Setara Semgrep & CodeQL) dengan deterministic SAST/IaC engine yang presisi, framework-aware, dan terukur sebelum memasuki AI Layer."

---

## Executive Overview & Sequential Execution Schedule

| Sprint | Fokus Utama | Target Status & Metrik Keberhasilan |
|---|---|---|
| **Sprint A3.0** | Rule Quality Infrastructure | Rule Validate, Lint, Docs Generator, Coverage Matrix CLI (**COMPLETED - 112 Rules**) |
| **Sprint A3.1** | PHP Security Pack | 25+ Rules, Framework-Aware (Laravel, Symfony, WP) (**COMPLETED - 27 PHP Rules**) |
| **Sprint A4** | Go Security Pack | 15-20 Rules, SSRF, SQLi, TLS, Command Injection, Secrets (**COMPLETED - 23 Go Rules**) |
| **Sprint A4.5** | Rule Quality Platform | Rule Profiler, Conflict Detector, Dead Code Detector (**COMPLETED - 126 Rules Total**) |
| **Sprint A6** | Shared Predicate Architecture | Resolution at YAML load time (`predicates/`), refactor existing rules (**ACTIVE NEXT**) |
| **Sprint A7** | Multi-Cloud IaC Security Pack | 55 Rules (Docker: 10, K8s: 15, TF AWS: 10, TF Azure: 5, TF GCP: 5, Helm: 5, GHA: 5) |
| **Sprint A5** | Rust Security Pack | 12-15 Rules (Axum, Actix, Warp, Rust Native) using Shared Predicates |
| **Sprint A8** | Rule Pack Refactoring & Cleanup | Deduplicate regex, merge rules, normalize metadata, CWE, OWASP, remediation |
| **Sprint A9** | Standalone Secrets Engine | Regex → Entropy → Checksum → Context Validation → Confidence score |
| **Sprint A10** | Framework Intelligence | Manifest scoring (`composer.json`, `package.json`, `go.mod`, `Cargo.toml`) |
| **Sprint A11** | Qualification Platform | Continuous qualification against OWASP Benchmark, Juliet, Juice Shop, DVWA |
| **Milestone B** | DevEx & Enterprise Integration | CLI Doctor, SARIF Diff, HTML/PDF Reports, Quality Gate Policy |
| **Milestone C** | AI Layer (Explain, Prioritize, Fix Draft) | Explain Findings, Risk Prioritization, Fix Draft, PR Security Copilot |

---

# Keputusan Arsitektur Kunci

1. **Shared Predicate Compile-Time Resolution**: Resolution dilakukan pada tahap loading YAML (`YAMLRuleLoader`). Memberikan performa scan maksimal, eksekusi deterministik, dan validasi penuh saat `karsasec rules validate`.
2. **Multi-Cloud IaC Balanced Distribution**: Penanganan IaC bersifat multi-cloud seimbang sejak awal (AWS, Azure, GCP, Docker, K8s, Helm, GHA).
