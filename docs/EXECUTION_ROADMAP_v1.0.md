# 🚀 KarsaSec v1.0 Roadmap (Revisi Enterprise)

**Platform:** KarsaSec Secure Code Analysis Platform (SecOS)  
**Versi Roadmap:** 1.0.0 (Enterprise Revision) | **Status:** Milestone 1 Active — Detection Quality Focus  
**Visi Utama:** "KarsaSec menjadi salah satu platform Application Security Open Source terbaik (Setara Semgrep) dengan deterministic SAST engine yang presisi, sebelum memasuki AI Layer."

---

## 🎯 Executive Overview & Prioritas Eksekusi

| Prioritas | Milestone | Fokus Utama | Target Status |
|---|---|---|---|
| ⭐⭐⭐⭐⭐ | **MILESTONE 1** | **Detection Quality (Target: Setara Semgrep)** | 120–150 rule, Precision >95%, FPR <5% (ACTIVE) |
| ⭐⭐⭐⭐☆ | **MILESTONE 2** | **Developer Experience & CLI** | Interactive CLI, Rule Lifecycle (`list`/`inspect`/`doctor`), `karsasec.yaml`, Docs |
| ⭐⭐⭐⭐☆ | **MILESTONE 3** | **Enterprise Integration** | Quality Gates (`--fail-on`), HTML/PDF Reporting, CI/CD Templates, OWASP Benchmark |
| ⭐⭐⭐☆☆ | **MILESTONE 4** | **Platform Ecosystem** | Plugin SDK, Rule Registry (`install`/`update`), Language SDKs (Java, C#, Ruby, Kotlin) |
| ⭐⭐☆☆☆ | **MILESTONE 5** | **AI Layer (Tahap Terakhir)** | AI Reasoning Consumer (Explain, Prioritize, Fix Draft, PR Review) |

---

# 🛡️ MILESTONE 1 — Detection Quality (Target: Setara Semgrep)

> **Prinsip:** "Jika user menjalankan `karsasec scan .`, hasilnya harus bisa dipercaya."

## A1 — Python Security Pack
- [x] **Injection**: SQLi, Command Injection, LDAP Injection, XPath Injection, SSTI (Jinja2/Mako), NoSQL Injection
- [x] **Serialization**: Pickle (`pickle.loads`), Marshal, Unsafe YAML (`yaml.load`), Dill, Shelve
- [x] **Crypto**: AES-ECB Mode, DES, RC4, MD5, SHA1, Pseudo-Random, Weak Salt
- [x] **Filesystem**: Zip Slip, Path Traversal, Temporary File (`tempfile.mktemp`), Unsafe Symlink
- [x] **Web**: SSRF, XXE, Open Redirect, CRLF Injection
- [x] **Flask Framework**: `SECRET_KEY`, Debug Mode (`debug=True`), Insecure Session Cookie, Missing CSRF
- [x] **Django Framework**: `DEBUG=True`, `ALLOWED_HOSTS=['*']`, Hardcoded `SECRET_KEY`, CSRF Middleware Exempt, `SECURE_SSL_REDIRECT=False`

**Definition of Done (DoD) per Rule:**
- [x] `vulnerable` fixture
- [x] `safe` fixture
- [x] AST test
- [x] Taint verification
- [x] Guard verification
- [x] SARIF snapshot

---

## A2 — JavaScript / TypeScript Security Pack
**Framework Target:** Express, Next.js, NestJS, Fastify
- [ ] DOM XSS (`innerHTML`, `document.write`)
- [ ] Reflected & Stored XSS
- [ ] Prototype Pollution (`lodash.merge`, object assign)
- [ ] Dangerous `eval()` & `new Function()`
- [ ] Command Injection (`child_process.exec`, `spawn` with shell)
- [ ] Insecure Cookie Flags & Hardcoded JWT Secret
- [ ] Open Redirect & SSRF (`axios`, `got`, `node-fetch`)
- [ ] Next.js Middleware Security & Header Bypasses

---

## A3 — PHP Security Pack
**Framework Target:** Laravel, Symfony, WordPress, Native PHP
- [ ] SQL Injection (PDO raw, mysqli)
- [ ] LFI / RFI / Path Traversal (`include`, `require` with user input)
- [ ] Unsafe Object Injection (`unserialize()`)
- [ ] Unsafe File Upload
- [ ] XSS (`echo $_GET` without escaping)
- [ ] Insecure Session Cookie Flags

---

## A4 — Go Security Pack
**Framework Target:** Gin, Echo, Fiber, Standard Library
- [ ] SSRF (`http.Get` dynamic URL)
- [ ] SQL Injection (`db.Query` string formatting)
- [ ] Unsafe Pointer (`unsafe.Pointer`)
- [ ] Insecure TLS (`InsecureSkipVerify: true`)
- [ ] Hardcoded API Secret
- [ ] Command Execution (`exec.Command("sh", "-c", ...)`)

---

## A5 — Rust Security Pack
**Framework Target:** Axum, Actix-web, Warp
- [ ] Unsafe Block Misuse (`unsafe { ... }`)
- [ ] Command Injection (`Command::new("sh")`)
- [ ] Hardcoded API Credentials
- [ ] Raw SQL Query Concatenation

---

## A6 — IaC Security Pack
- **Docker:** `USER` missing (Root container), `latest` tag, `curl | bash`, `ADD` vs `COPY`, `HEALTHCHECK` missing, Secrets in ENV
- **Kubernetes:** `privileged: true`, `hostNetwork`, `hostPID`, `hostPath`, `capabilities`, `runAsRoot`, resource limits missing
- **Terraform:** Public S3 bucket, Open Security Group (`0.0.0.0/0`), Wildcard IAM Policy (`*`)
- **Helm & GitHub Actions:** `pull_request_target`, unpinned actions, script injection, secret leakage

---

# 💻 MILESTONE 2 — Developer Experience (DevEx)

## B1 — CLI Enhancements
```bash
karsasec scan .
karsasec scan --severity HIGH
karsasec scan --framework flask
karsasec scan --rule KS-PY-0012
karsasec scan --new-only
karsasec scan --profile
```

## B2 — Rule Lifecycle Management
```bash
karsasec rules list
karsasec rules inspect <rule_id>
karsasec rules search <query>
karsasec rules doctor
karsasec rules validate
```

## B3 — Configuration Engine (`karsasec.yaml`)
Support for: `baseline`, `suppression`, `severity_override`, `rule_enable`, `plugins`, `rag`.

## B4 — Documentation
Comprehensive guides: Installation, Rule Authoring, Parser SDK, Plugin SDK, Architecture, Examples, CI/CD, Troubleshooting.

---

# 🏢 MILESTONE 3 — Enterprise Integration

- **C1 Quality Gates:** `--fail-on <SEVERITY>`, `--max-findings`, `--baseline`, `--new-only`. (Policy: HIGH/CRITICAL ➡️ Pipeline FAIL with consistent exit code).
- **C2 Reporting:** Console, JSON, SARIF 2.1.0, HTML Interactive Dashboard, Markdown, CSV, PDF.
- **C3 CI/CD Integration:** Official templates for GitHub Actions, GitLab CI, Azure DevOps, Jenkins, CircleCI, Bitbucket.
- **C4 Qualification & Benchmark:** OWASP Benchmark, Juliet Test Suite, DVWA, WebGoat, Juice Shop. Published metrics: Precision (≥95%), Recall (≥90%), F1 Score, FPR (≤5%), Scan Time, Memory Usage.

---

# 🔌 MILESTONE 4 — Platform Ecosystem

- **Plugin Marketplace:** Parser plugins, Rule plugins, Reporter plugins, Policy plugins.
- **Rule Registry:** `karsasec rules install`, `karsasec rules update`, `karsasec rules publish`.
- **SDKs:** Python SDK, Library API, REST API.
- **Language SDK:** Extensible SDK allowing third-party developers to build parsers for Java, C#, Swift, Kotlin, Ruby without touching the core engine.

---

# 🤖 MILESTONE 5 — AI Layer (Tahap Terakhir)

AI sebagai **consumer** dari hasil analisis deterministik engine:

```text
              Source Code
                    │
                    ▼
          Parser + Rule Engine
                    │
                    ▼
          AST / CFG / Dataflow
                    │
                    ▼
             Finding Objects
                    │
      ┌─────────────┼─────────────┐
      ▼             ▼             ▼
 Reporter      Baseline      SARIF Export
                    │
                    ▼
             AI Reasoning Layer
      ┌─────────────┼─────────────┐
      ▼             ▼             ▼
 Explain      Prioritize      Fix Draft
                    │
                    ▼
         Human Review & Apply
```

- **Capabilities:** Contextual Explanation, Severity Prioritization based on reachability, Fix Draft Generation (AST/diff validated), Multi-remediation trade-offs, PR Review Assistant.

---

## 🏆 KarsaSec v1.0 Production Gate Criteria

Sebuah rilis v1.0 hanya boleh dinyatakan **Production Ready** apabila memenuhi seluruh kriteria berikut:
1. **120–150 High Quality Rules** dengan fixture `vulnerable` dan `safe` serta `regression` test pada setiap rule.
2. **Precision ≥ 95%**, **Recall ≥ 90%**, dan **False Positive Rate ≤ 5%** pada benchmark teruji.
3. **Dukungan parser stabil** untuk seluruh bahasa dan IaC yang diklaim.
4. **Output JSON, SARIF 2.1.0, HTML, dan Markdown** tervalidasi dan kompatibel penuh dengan GitHub Code Scanning.
5. **Integrasi CI/CD resmi** untuk platform CI/CD utama.
6. **Dokumentasi lengkap** untuk pengguna, penulis rule, dan pengembang plugin.
