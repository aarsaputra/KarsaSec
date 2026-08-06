# KS-JAVA-0001: Java Server-Side Request Forgery (SSRF)

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-918
- **OWASP**: A10:2021-Server-Side Request Forgery (SSRF)
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: LanguageEnum.JAVA
- **Tags**: ssrf, network, java

## Description
Detects outbound HTTP requests constructed from untrusted inputs in Java applications.

## Remediation Strategy
Validate and whitelist destination URLs before sending HTTP requests.

## External References
- [https://cwe.mitre.org/data/definitions/918.html](https://cwe.mitre.org/data/definitions/918.html)
