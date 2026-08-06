# KS-PHP-CRYPTO-0001: PHP Weak Cryptography

## Metadata
- **Severity**: HIGH
- **Confidence**: LIKELY
- **CWE**: CWE-326
- **OWASP**: A02:2021-Cryptographic Failures
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: crypto

## Description
Detects use of weak or insecure cryptographic primitives in PHP.

## Remediation Strategy
Use modern crypto APIs like `password_hash`/`password_verify` and libs for encryption.

## External References
- [https://owasp.org/Top10/](https://owasp.org/Top10/)
