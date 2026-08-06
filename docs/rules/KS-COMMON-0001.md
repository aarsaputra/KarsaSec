# KS-COMMON-0001: Hardcoded Secrets Detection

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-798
- **OWASP**: A07:2021-Identification and Authentication Failures
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: LanguageEnum.PYTHON, LanguageEnum.JAVASCRIPT, LanguageEnum.PHP, LanguageEnum.GO
- **Tags**: secret, credential, common

## Description
Detects hardcoded secret tokens, private keys, or credentials stored in source files.

## Remediation Strategy
Store credentials in environment variables or a secure key vault (e.g. HashiCorp Vault).

## External References
- [https://cwe.mitre.org/data/definitions/798.html](https://cwe.mitre.org/data/definitions/798.html)
