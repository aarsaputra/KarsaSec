# KS-HTML-0002: HTML Unescaped Template Expression XSS

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-79
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.HTML
- **Tags**: xss, html, templates

## Description
Unescaped template expressions (v-html, raw triple braces) bypass HTML entity encoding, risking Reflected/Stored XSS.

## Remediation Strategy
Use auto-escaped template interpolation or sanitize HTML input using DOMPurify before rendering.

## External References
- [https://cwe.mitre.org/data/definitions/79.html](https://cwe.mitre.org/data/definitions/79.html)
