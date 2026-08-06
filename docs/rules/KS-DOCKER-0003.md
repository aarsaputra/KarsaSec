# KS-DOCKER-0003: Dockerfile Use of ADD Instead of COPY

## Metadata
- **Severity**: LOW
- **Confidence**: CONFIDENT
- **CWE**: CWE-703
- **OWASP**: A05:2021-Security Misconfiguration
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: TargetFormatEnum.DOCKERFILE
- **Tags**: docker, add, iac

## Description
Use of ADD instruction for local file copying instead of COPY.

## Remediation Strategy
Replace ADD with COPY for local files to avoid unexpected tar auto-extraction or remote URL fetches.

## External References
- [https://cwe.mitre.org/data/definitions/703.html](https://cwe.mitre.org/data/definitions/703.html)
