# KS-DOCKER-0002: Dockerfile Unpinned Base Image Tag

## Metadata
- **Severity**: MEDIUM
- **Confidence**: CONFIDENT
- **CWE**: CWE-1104
- **OWASP**: A05:2021-Security Misconfiguration
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: TargetFormatEnum.DOCKERFILE
- **Tags**: docker, image, iac

## Description
Base image tag is missing or set to latest, leading to non-deterministic builds.

## Remediation Strategy
Pin base image to an explicit version tag or immutable SHA digest.

## External References
- [https://cwe.mitre.org/data/definitions/1104.html](https://cwe.mitre.org/data/definitions/1104.html)
