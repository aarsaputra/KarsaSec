# KS-PHP-0013: PHP NoSQL Injection

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-943
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: nosql, injection, php

## Description
Passing unvalidated array inputs into MongoDB queries can alter operator logic (e.g. $ne, $gt) leading to authentication bypass.

## Remediation Strategy
Cast request parameters to string or validate types prior to querying NoSQL databases.

## External References
- [https://cwe.mitre.org/data/definitions/943.html](https://cwe.mitre.org/data/definitions/943.html)
