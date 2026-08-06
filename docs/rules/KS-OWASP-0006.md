# KS-OWASP-0006: OWASP A06 - Vulnerable and Outdated Components (Multi-language)

## Metadata
- **Severity**: MEDIUM
- **Confidence**: LIKELY
- **CWE**: CWE-1104
- **OWASP**: A06:2021-Vulnerable and Outdated Components
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP, LanguageEnum.PYTHON, LanguageEnum.JAVASCRIPT, LanguageEnum.GO, LanguageEnum.GENERIC
- **Tags**: scc

## Description
Detects usage of manifest files; integrate with SCA toolchain to lookup known vulnerable dependencies.

## Remediation Strategy
Run SCA scanning and upgrade or mitigate vulnerable packages.

## External References
- [https://owasp.org/Top10/](https://owasp.org/Top10/)
