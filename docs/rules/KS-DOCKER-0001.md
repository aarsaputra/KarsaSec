# KS-DOCKER-0001: Dockerfile Container Running as Root

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-250
- **OWASP**: A05:2021-Security Misconfiguration
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: TargetFormatEnum.DOCKERFILE
- **Tags**: docker, root, iac

## Description
Container explicitly sets execution user to root or 0.

## Remediation Strategy
Specify a dedicated non-root user (e.g. USER appuser) in your Dockerfile.

## External References
- [https://cwe.mitre.org/data/definitions/250.html](https://cwe.mitre.org/data/definitions/250.html)
