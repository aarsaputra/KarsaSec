# KS-OWASP-0008: OWASP A08 - Software and Data Integrity Failures / Insecure Deserialization

## Metadata
- **Severity**: HIGH
- **Confidence**: LIKELY
- **CWE**: CWE-502
- **OWASP**: A08:2021-Software and Data Integrity Failures
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP, LanguageEnum.PYTHON, LanguageEnum.JAVASCRIPT, LanguageEnum.GO, LanguageEnum.GENERIC
- **Tags**: deserialization

## Description
Unsafe deserialization or unverified package loading detected.

## Remediation Strategy
Validate payload signatures or use safe serialization formats (JSON, SafeLoader).

## External References
- [https://owasp.org/Top10/](https://owasp.org/Top10/)
