# KS-PHP-SSRF-0001: PHP SSRF

## Metadata
- **Severity**: HIGH
- **Confidence**: LIKELY
- **CWE**: CWE-918
- **OWASP**: A10:2021-Server-Side Request Forgery
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: ssrf

## Description
Detects potential SSRF when untrusted input is used to make outbound requests or file reads.

## Remediation Strategy
Whitelist destination hosts and validate URLs; avoid direct use of user-controlled URLs.

## External References
- [https://owasp.org/Top10/](https://owasp.org/Top10/)
