# KS-PHP-AUTH-0001: PHP Identification and Authentication Failures

## Metadata
- **Severity**: HIGH
- **Confidence**: LIKELY
- **CWE**: CWE-287
- **OWASP**: A07:2021-Identification and Authentication Failures
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: authentication

## Description
Detects potentially insecure authentication handling or weak password hashing calls.

## Remediation Strategy
Use `password_hash`/`password_verify` or modern KDFs and avoid MD5/SHA1 for password storage.

## External References
- [https://owasp.org/Top10/](https://owasp.org/Top10/)
