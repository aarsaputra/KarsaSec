# KS-PHP-0021: Laravel Debug Mode Enabled

## Metadata
- **Severity**: MEDIUM
- **Confidence**: CONFIDENT
- **CWE**: CWE-215
- **OWASP**: A05:2021-Security Misconfiguration
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: misconfig, laravel

## Description
APP_DEBUG=true exposes full stack traces, database credentials, and secret keys on application errors.

## Remediation Strategy
Set APP_DEBUG=false in production environment configurations.

## External References
- [https://cwe.mitre.org/data/definitions/215.html](https://cwe.mitre.org/data/definitions/215.html)
