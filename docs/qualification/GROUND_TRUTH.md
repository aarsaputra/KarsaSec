# Ground Truth Authoring & Anti-Circularity Specification

Ground truth defines the **expected security behavior** of a benchmark target.

---

## Anti-Circularity Principles

> **Rule 1**: Ground truth MUST be derived from manual code inspection or standard vulnerability specifications.
> **Rule 2**: Ground truth MUST NOT be generated automatically from KarsaSec scan output.
> **Rule 3**: Do NOT encode scanner flaws into ground truth (e.g., classifying a scanner false positive as `TRUE_POSITIVE` just to pass tests).

---

## Expectations

Each case in a `manifest.yaml` specifies an expectation:

- **`TRUE_POSITIVE`**: A real vulnerability exists at this exact file and line. KarsaSec **MUST** detect it.
- **`TRUE_NEGATIVE`**: Code is safe (or sanitized). KarsaSec **MUST NOT** produce a finding at this location.

---

## Manifest Schema

```yaml
benchmark:
  id: "dvwa"
  version: "1.x"
  description: "Damn Vulnerable Web Application Benchmark"

cases:
  - id: "dvwa-sqli-low-001"
    file: "vulnerabilities/sqli/source/low.php"
    line: 10
    rule_id: "KS-PHP-0002"
    expected: "TRUE_POSITIVE"
    cwe: "CWE-89"
    language: "PHP"
    severity: "HIGH"
    description: "Unsanitized $_REQUEST['id'] concatenated directly into SELECT query."
```
