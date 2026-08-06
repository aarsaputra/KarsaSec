# KS-PHP-0022: Laravel Mass Assignment Vulnerability

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-915
- **OWASP**: A08:2021-Software and Data Integrity Failures
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: mass_assignment, laravel

## Description
Passing unvalidated $request->all() directly into Eloquent fill() or create() allows unauthorized field mutation.

## Remediation Strategy
Use FormRequest validation or $request->only([...]) / $request->validated() to restrict mass-assignable attributes.

## External References
- [https://cwe.mitre.org/data/definitions/915.html](https://cwe.mitre.org/data/definitions/915.html)
