# KS-OWASP-0003: OWASP A03 - Injection (Multi-language)

## Metadata
- **Severity**: CRITICAL
- **Confidence**: LIKELY
- **CWE**: CWE-74
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP, LanguageEnum.PYTHON, LanguageEnum.JAVASCRIPT, LanguageEnum.GO, LanguageEnum.GENERIC
- **Tags**: injection

## Description
Detects dangerous sink invocation without adequate validation causing command, SQL, or code injection.

## Remediation Strategy
Parameterize all database queries, escape command arguments, or avoid dynamic command/code evaluation.

## External References
- [https://owasp.org/Top10/](https://owasp.org/Top10/)
