# KS-GHA-0003: GitHub Actions Unpinned Third-Party Action

## Metadata
- **Severity**: MEDIUM
- **Confidence**: CONFIDENT
- **CWE**: CWE-829
- **OWASP**: A08:2021-Software and Data Integrity Failures
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: TargetFormatEnum.GITHUB_ACTIONS
- **Tags**: github_actions, supply_chain, iac

## Description
Action uses mutable version tag instead of full 40-character commit SHA digest.

## Remediation Strategy
Pin action reference to a full commit SHA hash (e.g. actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11).

## External References
- [https://cwe.mitre.org/data/definitions/829.html](https://cwe.mitre.org/data/definitions/829.html)
