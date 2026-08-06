# KS-PHP-0003: PHP Unsafe File Inclusion and Path Traversal

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-22
- **OWASP**: A01:2021-Broken Access Control
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: path_traversal, include, php

## Description
Detects dynamic file inclusion or file reading utilizing unsanitized global request variables in PHP.

## Remediation Strategy
Avoid passing user input to file inclusion functions; use strict whitelist mapping instead.

## External References
- [https://cwe.mitre.org/data/definitions/22.html](https://cwe.mitre.org/data/definitions/22.html)
