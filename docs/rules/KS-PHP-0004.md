# KS-PHP-0004: PHP Local File Inclusion (LFI)

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-98
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: lfi, include, php

## Description
Detects dynamic file inclusion via include_once or require_once with user inputs.

## Remediation Strategy
Hardcode allowed file targets or resolve inputs via an array lookup whitelist.

## External References
- [https://cwe.mitre.org/data/definitions/98.html](https://cwe.mitre.org/data/definitions/98.html)
