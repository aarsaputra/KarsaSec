# KS-PHP-0002: PHP SQL Injection

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-89
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: sqli, database, php

## Description
Detects PHP database queries constructed via un-sanitized string concatenation.

## Remediation Strategy
Use prepared PDO statements with bindParam or mysqli prepare.

## External References
- [https://cwe.mitre.org/data/definitions/89.html](https://cwe.mitre.org/data/definitions/89.html)
