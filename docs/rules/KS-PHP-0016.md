# KS-PHP-0016: PHP Unrestricted File Upload

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-434
- **OWASP**: A04:2021-Insecure Design
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: upload, rce, php

## Description
Moving uploaded files into public web root without strict extension and MIME validation can allow executable PHP web shell deployment.

## Remediation Strategy
Re-encode images, generate random file names, enforce extension allowlists, and store uploads outside document root.

## External References
- [https://cwe.mitre.org/data/definitions/434.html](https://cwe.mitre.org/data/definitions/434.html)
