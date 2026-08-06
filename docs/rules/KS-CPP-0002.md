# KS-CPP-0002: C/C++ Weak Pseudo-Random Number Generator

## Metadata
- **Severity**: MEDIUM
- **Confidence**: CONFIDENT
- **CWE**: CWE-338
- **OWASP**: A02:2021-Cryptographic Failures
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.CPP
- **Tags**: crypto, random, cpp

## Description
Standard rand() or srand() functions are predictable and unsuitable for security-sensitive operations.

## Remediation Strategy
Use C++11 <random> header with std::mt19937 or OS-level cryptographically secure random sources.

## External References
- [https://cwe.mitre.org/data/definitions/338.html](https://cwe.mitre.org/data/definitions/338.html)
