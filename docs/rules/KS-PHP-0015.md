# KS-PHP-0015: PHP Zip Slip Archive Extraction

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-22
- **OWASP**: A01:2021-Broken Access Control
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: zip_slip, path_traversal, php

## Description
Extracting ZIP archives without validating individual file entry paths risks overwriting arbitrary system files.

## Remediation Strategy
Validate that extracted target paths remain inside the intended destination directory before writing files.

## External References
- [https://cwe.mitre.org/data/definitions/22.html](https://cwe.mitre.org/data/definitions/22.html)
