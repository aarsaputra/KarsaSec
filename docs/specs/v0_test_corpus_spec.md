# Phase V0 — Real-World Test Corpus Specification

## Overview
This document specifies the structure, categories, and test cases of the **Real-World Security Test Corpus** used to validate the E9–E16 foundation engine during Phase V0.

---

## 1. Corpus Architecture & Category Coverage

The V0 Test Corpus comprises 11 primary vulnerability categories, each containing:
- **`vulnerable.py`**: A minimal, real-world snippet containing a genuine vulnerability.
- **`fixed.py`**: The exact same codebase with a standard, secure remediation applied.
- **`mutated.py`**: A syntactically altered variant to verify semantic sensitivity.
- **`metadata.json`**: Ground-truth specification including source line, sink line, vulnerability class, expected severity, expected E15 decision, and expected E16 admission.

```text
tests/v0_corpus/
├── sql_injection/
│   ├── metadata.json
│   ├── vulnerable.py
│   ├── fixed.py
│   └── mutated.py
├── xss/
├── ssrf/
├── path_traversal/
├── command_injection/
├── auth_flaws/
├── idor/
├── prototype_pollution/
├── ssti/
├── insecure_deserialization/
└── dependency_vulns/
```

---

## 2. Vulnerability Benchmark Cases

### Benchmark 1: SQL Injection (SQLi)
- **Vulnerable Variant**: Unsanitized string concatenation in `cursor.execute("SELECT * FROM users WHERE username='" + user_input + "'")`.
- **Fixed Variant**: Parameterized query `cursor.execute("SELECT * FROM users WHERE username=%s", (user_input,))`.
- **Mutated Variant**: Formatted f-string `cursor.execute(f"SELECT * FROM users WHERE username='{user_input}'")`.
- **Expected Result**:
  - `vulnerable.py` $\rightarrow$ Finding: `SQL_INJECTION`, Priority: `HIGH`, E15: `BLOCK`, E16: `BLOCKED`.
  - `fixed.py` $\rightarrow$ Finding: None, E15: `ALLOW`, E16: `APPROVED`.
  - `mutated.py` $\rightarrow$ Finding: `SQL_INJECTION`, Priority: `HIGH`, E15: `BLOCK`, E16: `BLOCKED`.

### Benchmark 2: Cross-Site Scripting (XSS)
- **Vulnerable Variant**: Direct reflection of HTTP query parameter into HTML response output without escaping.
- **Fixed Variant**: Escaped output using `html.escape(user_input)`.
- **Mutated Variant**: Improper custom sanitizer `user_input.replace("<script>", "")`.
- **Expected Result**:
  - `vulnerable.py` $\rightarrow$ Finding: `XSS`, Priority: `HIGH`, E15: `BLOCK`, E16: `BLOCKED`.
  - `fixed.py` $\rightarrow$ Finding: None, E15: `ALLOW`, E16: `APPROVED`.
  - `mutated.py` $\rightarrow$ Finding: `XSS` (Incomplete Sanitizer), Priority: `HIGH`, E15: `BLOCK`, E16: `BLOCKED`.

### Benchmark 3: Server-Side Request Forgery (SSRF)
- **Vulnerable Variant**: Untrusted URL parameter passed directly to `requests.get(user_url)`.
- **Fixed Variant**: Domain whitelist validation before fetch.
- **Expected Result**:
  - `vulnerable.py` $\rightarrow$ Finding: `SSRF`, Priority: `HIGH`, E15: `BLOCK`, E16: `BLOCKED`.
  - `fixed.py` $\rightarrow$ Finding: None, E15: `ALLOW`, E16: `APPROVED`.

### Benchmark 4: Path Traversal
- **Vulnerable Variant**: User-controlled filename passed to `open("/var/www/uploads/" + filename)`.
- **Fixed Variant**: Path normalization and base directory restriction using `os.path.abspath` and `startswith`.
- **Expected Result**:
  - `vulnerable.py` $\rightarrow$ Finding: `PATH_TRAVERSAL`, Priority: `HIGH`, E15: `BLOCK`, E16: `BLOCKED`.
  - `fixed.py` $\rightarrow$ Finding: None, E15: `ALLOW`, E16: `APPROVED`.

### Benchmark 5: Command Injection
- **Vulnerable Variant**: User-supplied hostname passed to `os.system("ping -c 1 " + host)` or `subprocess.Popen(..., shell=True)`.
- **Fixed Variant**: Argument array without shell wrapper `subprocess.Popen(["ping", "-c", "1", host], shell=False)`.
- **Expected Result**:
  - `vulnerable.py` $\rightarrow$ Finding: `COMMAND_INJECTION`, Priority: `CRITICAL`, E15: `BLOCK`, E16: `BLOCKED`.
  - `fixed.py` $\rightarrow$ Finding: None, E15: `ALLOW`, E16: `APPROVED`.

---

## 3. Ground-Truth Grounding Protocol
Ground-truth expectations are strictly decoupled from the analyzer output. The ground-truth metadata files are authored independently and locked via SHA-256 signatures prior to execution.
