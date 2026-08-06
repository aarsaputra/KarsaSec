# KS-CPP-0001: C/C++ Buffer Overflow Unsafe String Copy

## Metadata
- **Severity**: CRITICAL
- **Confidence**: CONFIDENT
- **CWE**: CWE-120
- **OWASP**: A06:2021-Vulnerable and Outdated Components
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.CPP
- **Tags**: memory_safety, buffer_overflow, cpp

## Description
Use of unbounded buffer functions like strcpy, gets, or sprintf poses buffer overflow vulnerabilities.

## Remediation Strategy
Replace with bounded alternatives like strncpy, snprintf, or std::string operations.

## External References
- [https://cwe.mitre.org/data/definitions/120.html](https://cwe.mitre.org/data/definitions/120.html)
