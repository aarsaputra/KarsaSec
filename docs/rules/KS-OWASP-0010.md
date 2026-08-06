# KS-OWASP-0010: OWASP A10 - Server-Side Request Forgery (SSRF)

## Metadata
- **Severity**: HIGH
- **Confidence**: LIKELY
- **CWE**: CWE-918
- **OWASP**: A10:2021-Server-Side Request Forgery (SSRF)
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP, LanguageEnum.PYTHON, LanguageEnum.JAVASCRIPT, LanguageEnum.GO, LanguageEnum.GENERIC
- **Tags**: ssrf

## Description
Detects outbound HTTP requests using unvalidated user input.

## Remediation Strategy
Enforce strict URL whitelisting and block internal network ranges (127.0.0.1, 169.254.169.254).

## External References
- [https://owasp.org/Top10/](https://owasp.org/Top10/)
