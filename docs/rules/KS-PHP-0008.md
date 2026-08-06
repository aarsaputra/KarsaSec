# KS-PHP-0008: PHP Broken Access Control

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-285
- **OWASP**: A01:2021-Broken Access Control
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: broken_access_control, authorization, php

## Description
Detects PHP access control decisions that depend on unsanitized request-controlled user identifiers or tokens.

## Remediation Strategy
Use server-side authorization checks based on authenticated session state and avoid using request-controlled IDs or cookies directly for access control.

## External References
- [https://owasp.org/Top10/](https://owasp.org/Top10/)
- [https://cwe.mitre.org/data/definitions/285.html](https://cwe.mitre.org/data/definitions/285.html)
