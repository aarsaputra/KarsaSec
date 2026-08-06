# KS-RUST-0001: Rust Server-Side Request Forgery (SSRF)

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-918
- **OWASP**: A10:2021-Server-Side Request Forgery (SSRF)
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: LanguageEnum.RUST
- **Tags**: ssrf, network, rust

## Description
Detects outbound HTTP requests constructed from untrusted inputs in Rust applications.

## Remediation Strategy
Validate, sanitize, and whitelist destination URLs before making outbound requests.

## External References
- [https://cwe.mitre.org/data/definitions/918.html](https://cwe.mitre.org/data/definitions/918.html)
