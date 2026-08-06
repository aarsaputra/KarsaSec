# KS-PHP-0005: PHP Remote File Inclusion (RFI)

## Metadata
- **Severity**: CRITICAL
- **Confidence**: CONFIDENT
- **CWE**: CWE-98
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: rfi, include, php

## Description
Detects HTTP/HTTPS remote URL inclusion in PHP include or require statements.

## Remediation Strategy
Disable allow_url_include in php.ini and only allow local file inclusion.

## External References
- [https://cwe.mitre.org/data/definitions/98.html](https://cwe.mitre.org/data/definitions/98.html)
