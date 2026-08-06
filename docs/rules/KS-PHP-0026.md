# KS-PHP-0026: Symfony Expression Language Injection

## Metadata
- **Severity**: CRITICAL
- **Confidence**: CONFIDENT
- **CWE**: CWE-94
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: rce, symfony, expression_language

## Description
Evaluating untrusted user expressions via Symfony ExpressionLanguage permits arbitrary code execution.

## Remediation Strategy
Restrict expression language input to static predefined configuration strings.

## External References
- [https://cwe.mitre.org/data/definitions/94.html](https://cwe.mitre.org/data/definitions/94.html)
