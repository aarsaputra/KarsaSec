# DVWA Ground-Truth Benchmark

This directory contains the ground-truth manifest for the **Damn Vulnerable Web Application (DVWA)** target.

---

## Files

- `manifest.yaml`: 32 manually verified ground-truth cases (22 TP, 10 TN).

---

## Execution

```bash
karsasec qualify --benchmark dvwa --target /path/to/dvwa/vulnerabilities
```
