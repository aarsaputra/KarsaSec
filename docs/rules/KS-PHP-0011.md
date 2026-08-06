# KS-PHP-0011: PHP LDAP Injection

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-90
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: ldap, injection, php

## Description
Constructing LDAP queries directly from request parameters allows attackers to alter LDAP filter logic.

## Remediation Strategy
Sanitize inputs using ldap_escape() before supplying arguments to ldap_search or ldap_bind.

## External References
- [https://cwe.mitre.org/data/definitions/90.html](https://cwe.mitre.org/data/definitions/90.html)
