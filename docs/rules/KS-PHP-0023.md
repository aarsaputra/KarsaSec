# KS-PHP-0023: Laravel Unescaped Blade Output XSS

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-79
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: xss, blade, laravel

## Description
Using unescaped Blade tags {!! $var !!} bypasses HTML entity encoding, creating Cross-Site Scripting vulnerabilities.

## Remediation Strategy
Use standard Blade escaping syntax {{ $var }} unless raw HTML rendering is explicitly sanitized.

## External References
- [https://cwe.mitre.org/data/definitions/79.html](https://cwe.mitre.org/data/definitions/79.html)
