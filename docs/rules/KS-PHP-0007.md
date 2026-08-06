# KS-PHP-0007: PHP Unsafe File Upload

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-434
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 2.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: upload, php

## Description
Detects move_uploaded_file calls saving uploaded files using original extensions or unvalidated filenames.

## Remediation Strategy
Rename uploaded files to randomly generated UUIDs and validate extensions against a strict whitelist.

## External References
- [https://cwe.mitre.org/data/definitions/434.html](https://cwe.mitre.org/data/definitions/434.html)
