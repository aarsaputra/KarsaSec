# KS-PHP-0012: PHP XPath Injection

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-643
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: xpath, injection, php

## Description
Untrusted user input in XPath expressions permits unauthorized extraction of XML document nodes.

## Remediation Strategy
Use parameterized XPath queries or strictly validate inputs against alphanumeric allowlists.

## External References
- [https://cwe.mitre.org/data/definitions/643.html](https://cwe.mitre.org/data/definitions/643.html)
