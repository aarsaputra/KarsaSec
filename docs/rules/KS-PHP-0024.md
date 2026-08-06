# KS-PHP-0024: WordPress Unprepared $wpdb Query SQL Injection

## Metadata
- **Severity**: HIGH
- **Confidence**: CONFIDENT
- **CWE**: CWE-89
- **OWASP**: A03:2021-Injection
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: sqli, wordpress, wpdb

## Description
Executing $wpdb database queries directly with request parameters without $wpdb->prepare() permits SQL injection.

## Remediation Strategy
Wrap dynamic query arguments using $wpdb->prepare("SELECT ... %s", $val).

## External References
- [https://cwe.mitre.org/data/definitions/89.html](https://cwe.mitre.org/data/definitions/89.html)
