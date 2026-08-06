# KS-DOCKER-0004: Dockerfile Pipe Remote Script to Shell (curl | sh)

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-829
- **OWASP**: A08:2021-Software and Data Integrity Failures
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: TargetFormatEnum.DOCKERFILE
- **Tags**: docker, rce, iac

## Description
RUN instruction pipes remote network scripts directly into shell interpreter without integrity check.

## Remediation Strategy
Download script to file, verify SHA256 checksum, and inspect before executing.

## External References
- [https://cwe.mitre.org/data/definitions/829.html](https://cwe.mitre.org/data/definitions/829.html)
