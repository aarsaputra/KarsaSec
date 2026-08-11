# Available Benchmarks

Overview of standardized benchmarks supported by `karsasec qualify`.

---

## 1. DVWA (`benchmarks/dvwa`)

- **Name**: Damn Vulnerable Web Application
- **Version**: 1.x
- **Target Location**: `/home/lota1337/pentest/DVWA/vulnerabilities`
- **Total Cases**: 32 (22 `TRUE_POSITIVE`, 10 `TRUE_NEGATIVE`)
- **Vulnerability Coverage**:
  - `KS-PHP-0002` (SQL Injection)
  - `KS-PHP-0003` (Path Traversal / Arbitrary Read)
  - `KS-PHP-0004` (Local File Inclusion / LFI)
  - `KS-OWASP-0003` (Command Injection / RCE)
  - `KS-OWASP-0002` (Weak Password Hashing)
