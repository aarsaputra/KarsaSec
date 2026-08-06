# 🚀 KarsaSec v1.0 Roadmap (Post Architecture Freeze)

**Platform:** KarsaSec Secure Code Analysis Platform (SecOS)  
**Versi Roadmap:** 1.0.0 | **Status:** Post Architecture Freeze — Phase A Execution  
**Strategi Utama:** Rule Intelligence Expansion ➡️ Developer Experience ➡️ Enterprise Integration

---

## 🎯 Objective

Menyelesaikan KarsaSec v1.0 sebagai **production-ready Secure Code Analysis Platform** yang memiliki:
- Deterministic SAST engine berpresisi tinggi
- Multi-language & Framework support (Python, JS/TS, PHP, Go, Rust, Java)
- IaC security scanning (Dockerfile, Kubernetes, GitHub Actions, Terraform)
- Enterprise reporting & CI/CD quality gates
- Developer-friendly CLI & rule lifecycle management
- Ready to serve as foundation for AI Remediation in v2.0 (AI ditunda hingga fondasi v1.0 stabil)

---

## 🧭 Strategic Execution Flow

```
PHASE A — Rule Intelligence Expansion
  ├── SPRINT A1: Python Security Pack (Auth, Injection, Filesystem, Serialization, Crypto, Network, Flask/Django)
  ├── SPRINT A2: JavaScript / TypeScript Security Pack (Express, Next.js, NestJS, Fastify)
  ├── SPRINT A3: PHP Security Pack (Laravel, Symfony, WordPress)
  ├── SPRINT A4: Go Security Pack (Gin, Echo, Fiber)
  ├── SPRINT A5: Rust Security Pack (Actix, Axum, Warp)
  └── SPRINT A6: IaC Security Pack (Docker, Kubernetes, GitHub Actions, Terraform)

PHASE B — Developer Experience (DevEx)
  ├── SPRINT B1: CLI UX (Severity, Language, & Framework Filters, Progress & Execution Profiling)
  ├── SPRINT B2: Rule Lifecycle Management (list, inspect, search, enable, disable, doctor, validate)
  ├── SPRINT B3: Workspace Configuration (karsasec.yaml full schema, baseline, suppressions, RAG)
  └── SPRINT B4: Production Documentation & SDK Guides

PHASE C — Enterprise Integration
  ├── SPRINT C1: Quality Gates (--fail-on, --max-findings, --baseline, --new-only)
  ├── SPRINT C2: Multi-Format Reporting (Console, JSON, SARIF 2.1, HTML, Markdown, CSV, PDF)
  ├── SPRINT C3: CI/CD Templates (GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI)
  └── SPRINT C4: Qualification & Benchmark (OWASP Benchmark, Juliet, DVWA, WebGoat, Juice Shop)
```

---

# 🔬 PHASE A — Rule Intelligence Expansion

## Goal
Meningkatkan kualitas engine deteksi (**Bukan sekadar jumlah rule, tapi kualitas, precision & framework coverage**).

Target Trajectory: `47 Rules` ➡️ `120+ High Quality Rules` ➡️ `Framework Coverage` ➡️ `CWE / OWASP / MITRE ATT&CK Mapping`

---

### 🐍 Sprint A1 — Python Security Pack
**Target Framework:** Flask, Django, FastAPI, Standard Library

- [ ] **Authentication**: Hardcoded Secret, Weak JWT Secret, Insecure Session, Missing CSRF
- [ ] **Injection**: SQL Injection, Command Injection, LDAP Injection, XPath Injection, NoSQL Injection
- [ ] **Filesystem**: Path Traversal, Zip Slip, Unsafe Temp File (`tempfile.mktemp`)
- [ ] **Serialization**: Pickle (`pickle.loads`), Unsafe YAML Loader (`yaml.load`), Marshal
- [ ] **Crypto**: MD5, SHA1, Weak Random (`random` module), AES-ECB Mode
- [ ] **Network**: SSRF, Open Redirect, XXE (`xml.etree` / `minidom`)
- [ ] **Flask Framework**: `SECRET_KEY` hardcoding, Debug Mode (`debug=True`), `host=0.0.0.0`
- [ ] **Django Framework**: `DEBUG=True`, `ALLOWED_HOSTS=['*']`, CSRF Middleware Exempt

**Definition of Done (DoD):**
- [ ] Vulnerable fixture created
- [ ] Safe fixture created
- [ ] AST test verified
- [ ] Taint/Guard test verified
- [ ] SARIF snapshot validated

---

### 🟨 Sprint A2 — JavaScript / TypeScript Security Pack
**Target Framework:** Express, Next.js, NestJS, Fastify

- [ ] XSS (Reflected / Stored)
- [ ] DOM XSS (`innerHTML`, `document.write`)
- [ ] Prototype Pollution (`lodash.merge`, object assign)
- [ ] JWT Secret Hardcoding
- [ ] Insecure Cookie Flags (`httpOnly: false`, `secure: false`)
- [ ] SSRF (`axios`, `node-fetch`, `got`)
- [ ] Open Redirect (`res.redirect`)
- [ ] `eval()` / `Function()` Injection
- [ ] Command Injection (`child_process.exec`)
- [ ] Weak Crypto (`crypto.createHash('md5')`)
- [ ] Weak CORS Configuration (`Access-Control-Allow-Origin: *`)
- [ ] Next.js Middleware Bypass & Security Headers

---

### 🐘 Sprint A3 — PHP Security Pack
**Target Framework:** Laravel, Symfony, WordPress, Native PHP

- [ ] SQL Injection (PDO raw, mysqli string concat)
- [ ] File Inclusion / Path Traversal (`include`, `require` with user input)
- [ ] Object Injection / Unserialize (`unserialize()`)
- [ ] Insecure Session Cookie Flags
- [ ] XSS (`echo $_GET[...]` without `htmlspecialchars`)
- [ ] CSRF Exemption
- [ ] Unsafe File Upload
- [ ] Command Injection (`exec`, `system`, `passthru`, `shell_exec`)

---

### 🐹 Sprint A4 — Go Security Pack
**Target Framework:** Gin, Echo, Fiber, Standard Library

- [ ] SSRF (`http.Get` with dynamic URL)
- [ ] SQL Injection (`db.Query` string formatting)
- [ ] Unsafe Pointer Usage (`unsafe.Pointer`)
- [ ] Weak TLS Configuration (`InsecureSkipVerify: true`)
- [ ] Hardcoded Secret / API Token
- [ ] Command Injection (`exec.Command` with bash -c)

---

### 🦀 Sprint A5 — Rust Security Pack
**Target Framework:** Actix-web, Axum, Warp

- [ ] Unsafe Block Misuse (`unsafe { ... }`)
- [ ] Command Injection (`Command::new("sh").arg("-c")`)
- [ ] Hardcoded API Credential
- [ ] SQL Query Concatenation

---

### 🐳 Sprint A6 — IaC & Cloud Security Pack
**Docker:** `USER` missing, `latest` tag, `curl | bash`, `ADD` vs `COPY`, `HEALTHCHECK` missing, Hardcoded Secrets  
**Kubernetes:** `privileged: true`, `hostNetwork`, `hostPID`, `hostPath`, `capabilities`, `runAsRoot`, resource limits  
**GitHub Actions:** `pull_request_target`, unpinned actions, script injection, secret leakage  
**Terraform:** Public S3 bucket, Open Security Group (`0.0.0.0/0`), Wildcard IAM Policy (`*`)

---

# 🛠️ PHASE B — Developer Experience (DevEx)

## Goal
Membuat developer nyaman dan produktif menggunakan KarsaSec setiap hari.

- **Sprint B1 — CLI UX:** `--severity`, `--rule`, `--language`, `--framework` filters, Rich progress bar, scan stats, execution profiler.
- **Sprint B2 — Rule Lifecycle Management:** `karsasec rules list`, `inspect`, `search`, `enable`, `disable`, `doctor`, `validate`.
- **Sprint B3 — Workspace Configuration:** Full `karsasec.yaml` schema, baseline, suppressions, RAG & plugin settings.
- **Sprint B4 — Documentation:** Installation, Rule Authoring, Parser SDK, Plugin SDK, CI/CD, Migration, & Troubleshooting Guides.

---

# 📦 PHASE C — Enterprise Integration

## Goal
Membuat KarsaSec siap digunakan dalam pipeline CI/CD enterprise.

- **Sprint C1 — Quality Gates:** `--fail-on`, `--max-findings`, `--baseline`, `--new-only` (Quality Gate policy: HIGH/CRITICAL ➡️ Pipeline FAIL).
- **Sprint C2 — Multi-Format Reporting:** Console, JSON, SARIF 2.1.0 (validated for GitHub Code Scanning), HTML (Dark mode interactive), Markdown, CSV, PDF.
- **Sprint C3 — CI/CD Templates:** Official templates for GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI.
- **Sprint C4 — Qualification & Benchmark:** OWASP Benchmark, Juliet Test Suite, DVWA, WebGoat, Juice Shop. Published metrics: Precision (≥90%), Recall (≥90%), F1 Score, Scan Time, Memory Usage, Rule & Framework Coverage.

---

## 🏆 Definition of Done v1.0

KarsaSec v1.0 dinyatakan siap rilis apabila memenuhi seluruh kriteria berikut:
1. **120+ High Quality Rules** dengan fixture `vulnerable`/`safe` dan `regression` test pada setiap rule.
2. **Multi-language & Framework Support** stabil (Python, JS/TS, PHP, Go, Rust, Java) beserta IaC (Dockerfile, Kubernetes, GitHub Actions, Terraform).
3. **Precision ≥ 90%** pada benchmark internal & external dengan **False Positive Rate < 10%**.
4. **SARIF 2.1.0** tervalidasi dan kompatibel penuh dengan GitHub Code Scanning.
5. **CLI, dokumentasi, dan CI/CD templates** lengkap dan siap pakai.
6. **Test suite lulus 100%** serta benchmark performa terdokumentasi secara transparan.
