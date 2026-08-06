# KS-PHP-DESER-0001: PHP Insecure Deserialization

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-502
- **OWASP**: A08:2021-Insecure Deserialization
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: deserialization

## Description
Detects deserialization of potentially untrusted PHP serialized data.

## Remediation Strategy
Avoid unserialize on untrusted data; use json_decode or safe parsers instead.

## External References
- [https://owasp.org/Top10/](https://owasp.org/Top10/)
