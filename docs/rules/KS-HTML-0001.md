# KS-HTML-0001: HTML Inline Event Handler XSS Flaw

## Metadata
- **Severity**: MEDIUM
- **Confidence**: CONFIDENT
- **CWE**: CWE-79
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.HTML
- **Tags**: xss, html, frontend

## Description
Inline event handlers in HTML templates increase XSS attack surface and violate Content Security Policy.

## Remediation Strategy
Attach event handlers in external JavaScript files using addEventListener and enforce strict CSP header.

## External References
- [https://cwe.mitre.org/data/definitions/79.html](https://cwe.mitre.org/data/definitions/79.html)
