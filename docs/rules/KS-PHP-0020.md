# KS-PHP-0020: Laravel Query Builder Raw SQL Injection

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-89
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: sqli, laravel, framework

## Description
Using DB::raw() or raw query clauses with concatenated request data introduces SQL injection.

## Remediation Strategy
Use array bindings or parameterized placeholders in raw Laravel query clauses.

## External References
- [https://cwe.mitre.org/data/definitions/89.html](https://cwe.mitre.org/data/definitions/89.html)
