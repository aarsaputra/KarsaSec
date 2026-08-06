# KS-GHA-0001: GitHub Actions Inline Script Injection

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-78
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: TargetFormatEnum.GITHUB_ACTIONS
- **Tags**: github_actions, injection, iac

## Description
Unescaped github.event expression expanded directly inside inline shell script.

## Remediation Strategy
Pass github.event values into environment variables (env:) before using in run script.

## External References
- [https://cwe.mitre.org/data/definitions/78.html](https://cwe.mitre.org/data/definitions/78.html)
