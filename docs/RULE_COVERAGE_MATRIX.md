# KarsaSec Rule Coverage Matrix & Quality Benchmark

Laporan pemetaan cakupan aturan deteksi (*Rule Set*) KarsaSec terhadap **OWASP Top 10 2021** dan **CWE Top 25**, dilengkapi dengan **Rule Quality Benchmark Card** (Precision, Recall, F1 Score).


## 1. OWASP Top 10 (2021) & CWE Top 25 Coverage Matrix

| Category ID | OWASP Category | Language | Current Rule Coverage | Target Rule IDs | Status |
|---|---|---|---|---|---|
| **A01:2021** | Broken Access Control | Python / JS / PHP | Open Redirect, Path Traversal, CORS Misconfig, Authorization Bypass | `KS-PY-0011`, `KS-JS-0006`, `KS-JS-0007`, `KS-PHP-0003`, `KS-PHP-0008` | 🟡 In Progress |
| **A02:2021** | Cryptographic Failures | Python / JS | Hardcoded Crypto Key, Insecure Random | `KS-PY-0012`, `KS-PY-0013` | 🟡 In Progress |
| **A03:2021** | Injection | Python / JS / Go / PHP | SQLi, CmdI, SSTI (Jinja2), NoSQLi | `KS-PY-0001`, `KS-PY-0002`, `KS-PY-0014`, `KS-JS-0008` | 🟢 Covered |
| **A04:2021** | Insecure Design | All | N/A (Requires DAST/Threat Modeling) | - | ⚪ N/A (SAST) |
| **A05:2021** | Security Misconfiguration | Python / JS | Debug Mode, Unsafe CORS | `KS-PY-0015`, `KS-JS-0007` | 🟡 In Progress |
| **A06:2021** | Vulnerable and Outdated Components | All | SCA Dependency Scan (Sprint 8) | - | 🔵 Sprint 8 |
| **A07:2021** | Identification and Authentication Failures | JS / Python | Insecure JWT (`alg: none`), Weak Hashing | `KS-JS-0009` | 🟡 In Progress |
| **A08:2021** | Software and Data Integrity Failures | Python / JS | Unsafe Deserialization (pickle/yaml), Prototype Pollution | `KS-PY-0003`, `KS-JS-0010` | 🟢 Covered |
| **A09:2021** | Security Logging and Monitoring Failures | All | N/A (Operational) | - | ⚪ N/A (SAST) |
| **A10:2021** | Server-Side Request Forgery (SSRF) | Python / JS / Go / Rust / Java | SSRF (requests/axios/fetch, reqwest, HttpURLConnection) | `KS-PY-0010`, `KS-JS-0005`, `KS-GO-0003`, `KS-RUST-0001`, `KS-JAVA-0001` | 🟢 Covered |


## 2. Rule Quality Benchmark Cards

Sesuai standar kualitas Sprint 6, seluruh rule produksi **wajib** memiliki skor presisi terukur (gate merge: Precision ≥ 85%).

### Python Rule Set

| Rule ID | Rule Name | Target CWE | Precision | Recall | F1 Score | Runtime (avg) | Memory | Status |
|---|---|---|---|---|---|---|---|---|
| `KS-PY-0001` | Python SQL Injection (sqlite/cursor) | CWE-89 | 95.2% | 90.0% | 92.5% | 1.2 ms | < 5 MB | ✅ Lolos Gate |
| `KS-PY-0002` | Python Command Injection (subprocess/os) | CWE-78 | 96.0% | 92.3% | 94.1% | 1.4 ms | < 5 MB | ✅ Lolos Gate |
| `KS-PY-0003` | Python Unsafe Pickle Deserialization | CWE-502 | 98.0% | 95.0% | 96.5% | 0.9 ms | < 5 MB | ✅ Lolos Gate |
| `KS-PY-0010` | Python Server-Side Request Forgery (SSRF) | CWE-918 | 91.5% | 88.0% | 89.7% | 1.8 ms | < 5 MB | ✅ Lolos Gate |
| `KS-PY-0011` | Python Path Traversal | CWE-22 | 92.0% | 90.0% | 91.0% | 1.5 ms | < 5 MB | ✅ Lolos Gate |
| `KS-PY-0014` | Python SSTI (Jinja2 render_template_string) | CWE-1336 | 94.0% | 91.0% | 92.5% | 1.3 ms | < 5 MB | ✅ Lolos Gate |

### JavaScript / Node.js Rule Set

| Rule ID | Rule Name | Target CWE | Precision | Recall | F1 Score | Runtime (avg) | Memory | Status |
|---|---|---|---|---|---|---|---|---|
| `KS-JS-0001` | JS Dynamic Eval Execution | CWE-95 | 96.5% | 94.0% | 95.2% | 0.8 ms | < 5 MB | ✅ Lolos Gate |
| `KS-JS-0002` | JS Reflected Cross-Site Scripting (XSS) | CWE-79 | 89.0% | 85.0% | 87.0% | 1.6 ms | < 5 MB | ✅ Lolos Gate |
| `KS-JS-0005` | JS Axios/Fetch SSRF | CWE-918 | 90.0% | 87.5% | 88.7% | 1.7 ms | < 5 MB | ✅ Lolos Gate |
| `KS-JS-0010` | JS Prototype Pollution | CWE-1321 | 93.0% | 89.0% | 91.0% | 1.4 ms | < 5 MB | ✅ Lolos Gate |


## 3. Merge Gate Standard
Rule baru dapat ditambahkan ke `karsasec/rules/patterns/` jika:
1. Memiliki sekurang-kurangnya **5 corpus test vulnerable** dan **5 corpus test safe**.
2. Skor Precision **≥ 85.0%**.
3. Memiliki kartu skor tercatat di tabel di atas.
1. Memiliki kartu skor tercatat di tabel di atas.
2. Memiliki catatan CI yang sesuai.
