# KS-PHP-0027: Symfony Twig Template Unescaped Raw Output SSTI

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-1336
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: ssti, twig, symfony

## Description
Applying the raw filter to request input in Twig templates allows XSS and template injection.

## Remediation Strategy
Remove the raw filter and rely on Twig auto-escaping or sanitize HTML content beforehand.

## External References
- [https://cwe.mitre.org/data/definitions/1336.html](https://cwe.mitre.org/data/definitions/1336.html)
