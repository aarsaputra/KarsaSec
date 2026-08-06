# KS-GHA-0002: GitHub Actions Dangerous pull_request_target Event

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-269
- **OWASP**: A05:2021-Security Misconfiguration
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: TargetFormatEnum.GITHUB_ACTIONS
- **Tags**: github_actions, trigger, iac

## Description
Workflow triggered by pull_request_target runs with write permissions and access to repository secrets.

## Remediation Strategy
Ensure PR code checkout is avoided or restricted to safe non-executing steps.

## External References
- [https://cwe.mitre.org/data/definitions/269.html](https://cwe.mitre.org/data/definitions/269.html)
