# KS-PHP-0014: PHP Phar Stream Deserialization

## Metadata
- **Severity**: CRITICAL
- **Confidence**: CONFIDENT
- **CWE**: CWE-502
- **OWASP**: A08:2021-Software and Data Integrity Failures
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: deserialization, phar, rce, php

## Description
Accessing phar:// URIs in filesystem functions triggers automatic metadata object deserialization.

## Remediation Strategy
Restrict protocol wrappers in filesystem calls and disable phar stream wrapper if unused.

## External References
- [https://cwe.mitre.org/data/definitions/502.html](https://cwe.mitre.org/data/definitions/502.html)
