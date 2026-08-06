# KS-PHP-0010: PHP Command Injection Flaw

## Metadata
- **Severity**: CRITICAL
- **Confidence**: CONFIDENT
- **CWE**: CWE-78
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: cmdi, rce, php

## Description
Passing unsanitized user inputs into system execution functions (exec, shell_exec, passthru) enables arbitrary OS command execution.

## Remediation Strategy
Escape parameters with escapeshellarg() or escapeshellcmd(), or avoid invoking system shells.

## External References
- [https://cwe.mitre.org/data/definitions/78.html](https://cwe.mitre.org/data/definitions/78.html)
