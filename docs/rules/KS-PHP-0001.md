# KS-PHP-0001: PHP Remote Code Execution

## Metadata
- **Severity**: CRITICAL
- **Confidence**: CONFIDENT
- **CWE**: CWE-78
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: rce, eval, php

## Description
Detects execution of system commands or PHP code strings from user input.

## Remediation Strategy
Avoid shell execution functions. Validate and sanitize inputs strictly using escapeshellarg.

## External References
- [https://cwe.mitre.org/data/definitions/78.html](https://cwe.mitre.org/data/definitions/78.html)
