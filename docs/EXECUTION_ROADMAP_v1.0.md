# KarsaSec v1.0 Roadmap (Revisi Enterprise)

Platform: KarsaSec Secure Code Analysis Platform (SecOS)
Versi Roadmap: 1.1.0 (Python Pack Granular Plan) | Status: Milestone 1 Active - Detection Quality Focus
Visi Utama: "KarsaSec menjadi salah satu platform Application Security Open Source terbaik (Setara Semgrep) dengan deterministic SAST engine yang presisi, sebelum memasuki AI Layer."

---

## Executive Overview & Prioritas Eksekusi

| Prioritas | Milestone | Fokus Utama | Target Status |
|---|---|---|---|
| P1 | MILESTONE 1 | Detection Quality (Target: Setara Semgrep) | 120-150 rule, Precision >=95%, Recall >=90%, FPR <=5% (ACTIVE) |
| P2 | MILESTONE 2 | Developer Experience & CLI | Interactive CLI, Rule Lifecycle (list/inspect/doctor), karsasec.yaml, Docs |
| P3 | MILESTONE 3 | Enterprise Integration | Quality Gates (--fail-on), HTML/PDF Reporting, CI/CD Templates, OWASP Benchmark |
| P4 | MILESTONE 4 | Platform Ecosystem | Plugin SDK, Rule Registry (install/update), Language SDKs (Java, C#, Ruby, Kotlin) |
| P5 | MILESTONE 5 | AI Layer (Tahap Terakhir) | AI Reasoning Consumer (Explain, Prioritize, Fix Draft, PR Review) |

---

# MILESTONE 1 - Detection Quality (Target: Setara Semgrep)

Prinsip: "Jika user menjalankan karsasec scan ., hasilnya harus bisa dipercaya."

Target Kualitas Milestone 1:
- 120-150 High Quality Rules
- Precision >= 95%
- Recall >= 90%
- False Positive Rate (FPR) <= 5%

## Sprint A1 - Python Security Pack Completion (Sub-Sprints A1.1 s/d A1.8)

### Sprint A1.1 - Core Injection & Web (DONE)
- SQLi, Command Injection, SSRF, XXE, Open Redirect, Path Traversal, Temp File

### Sprint A1.2 - Authentication & Session (ACTIVE)
- Hardcoded JWT Secret
- Flask Session Cookie Flags (Secure, HttpOnly, SameSite)
- Django Session Cookie Flags (SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY)
- Weak Password Hashing (MD5/SHA1 for passwords)
- Insecure Password Storage

### Sprint A1.3 - Python Filesystem
- Path Traversal (advanced)
- Symlink Attack / Arbitrary File Overwrite
- Insecure File Permission (chmod 0777)
- TOCTOU (Time-of-check to time-of-use)
- Directory Traversal & Unsafe Temp Dir

### Sprint A1.4 - Python Networking
- SSRF (requests, urllib, aiohttp)
- Insecure TLS (verify=False, ssl._create_unverified_context)
- Urllib SSL Disable
- Unencrypted Protocols (FTP, Telnet)

### Sprint A1.5 - Python Cryptography
- RSA Key Size < 2048
- ECB Cipher Mode
- Weak Algorithms (DES, RC2, RC4, Blowfish, MD4, MD5, SHA1)
- Predictable IV / Constant IV / Static Nonce

### Sprint A1.6 - Python Framework Pack (Flask & Django Full OWASP)
- Flask: debug=True, SECRET_KEY, send_file traversal, unsafe redirect, Jinja SSTI, CSRF exemption
- Django: DEBUG=True, ALLOWED_HOSTS=['*'], SECRET_KEY, csrf_exempt, SECURE_SSL_REDIRECT=False, X_FRAME_OPTIONS

### Sprint A1.7 - Python Benchmark Suite
- Complete security_corpus/python/ directory structure with metadata.yaml, safe/, vulnerable/ for all categories.

### Sprint A1.8 - Rule Quality Evaluator Tool
- Automated tool tools/evaluate.py providing Rule Coverage, Precision, Recall, FPR, Missed/Unexpected Findings, Runtime, Memory, and Top Slow Rules.

---

## Definition of Done (DoD) per Rule
Every rule MUST contain:
1. vulnerable fixture
2. safe fixture
3. AST test
4. Taint verification
5. Guard verification
6. SARIF snapshot validation
