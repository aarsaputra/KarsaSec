# KarsaSec v1.0 Roadmap (Revisi Enterprise)

Platform: KarsaSec Secure Code Analysis Platform (SecOS)
Versi Roadmap: 1.2.0 (Capabilities-Based & Comprehensive Roadmap) | Status: Milestone 1 Active - Detection Quality Focus
Visi Utama: "KarsaSec menjadi salah satu platform Application Security Open Source terbaik (Setara Semgrep) dengan deterministic SAST engine yang presisi, berorientasi kapabilitas deteksi, sebelum memasuki AI Layer."

---

## Executive Overview & Prioritas Eksekusi

| Prioritas | Milestone | Fokus Utama | Target Status |
|---|---|---|---|
| P1 | MILESTONE 1 | Detection Quality (Target: Setara Semgrep) | 120-150 rule, Precision >95%, FPR <5% (ACTIVE) |
| P2 | MILESTONE 2 | Developer Experience & CLI | Interactive CLI, Rule Lifecycle (list/inspect/doctor), karsasec.yaml, Docs |
| P3 | MILESTONE 3 | Enterprise Integration | Quality Gates (--fail-on), HTML/PDF Reporting, CI/CD Templates, Real Benchmark |
| P4 | MILESTONE 4 | Platform Ecosystem | Plugin Marketplace, Rule Registry (install/update), Language SDKs |
| P5 | MILESTONE 5 | AI Layer (Tahap Terakhir) | AI Reasoning Consumer (Explain, Prioritize, Fix Draft, PR Review) |

---

# MILESTONE 1 - Detection Quality (Target: Setara Semgrep)

Prinsip: "Jika user menjalankan karsasec scan ., hasilnya harus bisa dipercaya."

Target Kualitas Milestone 1:
- 120-150 High Quality Rules
- Precision >= 95%
- Recall >= 90%
- False Positive Rate (FPR) <= 5%

## Sprint A1 - Python Security Pack Completion (DONE)
- Sprint A1.1 s/d A1.8: Injection, Web, Auth, Session, Filesystem, Networking, Crypto, Framework (Flask/Django), Corpus Test Suite & Evaluator Tool.

## Sprint A2 - JavaScript / TypeScript Pack (ACTIVE)
- Express: Command Injection, SQL Injection, SSRF, Path Traversal, Open Redirect, JWT Secret, Hardcoded Secret, Cookie Flag, Helmet Missing, CORS Wildcard, Dangerous eval, child_process.exec/spawn, vm.runInNewContext.
- Next.js: Middleware bypass, Server Action security, Insecure cookies, Server Component secret leak, Route Handler SSRF, API Route SQLi, dangerouslySetInnerHTML, Prototype Pollution, Open Redirect, Image loader abuse.
- NestJS: ValidationPipe disabled, Raw SQL / TypeORM injection, Prisma unsafe query, JWT secret, Debug enabled.
- Fastify: reply.send(userInput) XSS, helmet disabled, CORS wildcard.

## Sprint A3 - PHP Pack
- Frameworks: Laravel, Symfony, WordPress, Native PHP.
- Coverage: SQLi, RCE, Object Injection, Deserialization, LFI/RFI, Path Traversal, Upload, Session, Cookie, Password, Open Redirect, XXE, SSRF.

## Sprint A4 - Go Pack
- Frameworks: Gin, Echo, Fiber.
- Coverage: Command Injection, SQLi, SSRF, TLS, Secrets, JWT, Unsafe Pointer, Crypto, File Permission.

## Sprint A5 - Rust Pack
- Frameworks: Axum, Actix, Warp.
- Coverage: unsafe block, Command, SQL, JWT, Secrets, TLS, Random.

## Sprint A6 - IaC Pack (Minimal 30 Rules)
- Coverage: Docker, Kubernetes, Terraform, Helm, GitHub Actions.
- Topics: Privilege Escalation, Capabilities, HostPath, runAsRoot, seccomp, NetworkPolicy, OIDC, Terraform state, Helm secrets.

## Sprint A7 - Secrets Detection Engine
- Engine khusus deteksi secret: AWS, Azure, GCP, JWT, RSA, SSH, OpenAI, GitHub, GitLab, Slack, Discord, Stripe, Twilio, Sendgrid, SMTP, Bearer Token, Private Key, API Key, Password, Database URL.

## Sprint A8 - Framework Intelligence
- Pengenalan otomatis framework dan versi library (misal: Python + Flask 3.x, Node.js + Express 4.x) untuk rule targeting presisi tinggi.

---

# MILESTONE 2 - Developer Experience

- Sprint B1: CLI Filtering (--severity, --framework, --language, --rule, --profile, --new-only, --stats)
- Sprint B2: Rule Lifecycle (list, inspect, search, validate, doctor, test)
- Sprint B3: Workspace Config (karsasec.yaml)
- Sprint B4: Documentation & SDK (Rule Author Guide, Parser SDK, Plugin SDK, Reporter SDK)

---

# MILESTONE 3 - Enterprise Integration

- Sprint C1: Quality Gates (--fail-on, --max-findings, --baseline, --new-only)
- Sprint C2: Multi-Format Reporter (HTML, Markdown, CSV, PDF, JUnit XML, GitLab SAST, GitHub Code Scanning)
- Sprint C3: CI/CD Templates (GitHub Actions, GitLab, Azure DevOps, Jenkins, CircleCI, Bitbucket)
- Sprint C4: Real Benchmark Validation (OWASP Benchmark, Juliet Test Suite, DVWA, WebGoat, Juice Shop, DVNA, Vulnerable Flask/Django)

---

# MILESTONE 4 - Platform Ecosystem

- Plugin Marketplace, Rule Registry, Auto Update Rules, Versioned Rule Pack, Community Rules, Language SDKs (Python, Java, C#, Kotlin, Ruby).

---

# MILESTONE 5 - AI Layer (Consumer of Deterministic Findings)

1. Explain Finding
2. Risk Prioritization
3. Fix Draft Generation
4. Pull Request Review
5. Secure Coding Assistant
6. Security Copilot
