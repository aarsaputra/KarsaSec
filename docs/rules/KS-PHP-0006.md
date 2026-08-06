# KS-PHP-0006: PHP Object Injection (unserialize)

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-502
- **OWASP**: A08:2021-Software and Data Integrity Failures
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: deserialization, object_injection, php

## Description
Detects unserialize calls on user-supplied strings, leading to PHP Object Injection and potential RCE.

## Remediation Strategy
Avoid unserialize on untrusted input; use JSON format (json_decode) or specify allowed_classes option.

## External References
- [https://cwe.mitre.org/data/definitions/502.html](https://cwe.mitre.org/data/definitions/502.html)
