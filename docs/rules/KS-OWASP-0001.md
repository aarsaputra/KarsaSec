# KS-OWASP-0001: OWASP A01 - Broken Access Control (Multi-language)

## Metadata
- **Severity**: HIGH
- **Confidence**: LIKELY
- **CWE**: CWE-284
- **OWASP**: A01:2021-Broken Access Control
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP, LanguageEnum.PYTHON, LanguageEnum.JAVASCRIPT, LanguageEnum.GO, LanguageEnum.GENERIC
- **Tags**: broken_access_control, authorization

## Description
Detects code paths making access control decisions based on request-controlled values or weak token checks.

## Remediation Strategy
Use server-side authoritative identity checks and avoid using client-controlled cookies or request parameters for authorization.

## External References
- [https://owasp.org/Top10/](https://owasp.org/Top10/)
