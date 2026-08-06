# KS-DOCKER-0005: Dockerfile Hardcoded Secret in ENV or ARG

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-798
- **OWASP**: A07:2021-Identification and Authentication Failures
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: TargetFormatEnum.DOCKERFILE
- **Tags**: docker, secret, iac

## Description
Hardcoded credentials or tokens exposed in ENV or ARG instructions.

## Remediation Strategy
Inject secrets at runtime using container secrets management or environment variables at launch.

## External References
- [https://cwe.mitre.org/data/definitions/798.html](https://cwe.mitre.org/data/definitions/798.html)
