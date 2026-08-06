# KS-PHP-0025: WordPress Missing Nonce CSRF Verification

## Metadata
- **Severity**: MEDIUM
- **Confidence**: LIKELY
- **CWE**: CWE-352
- **OWASP**: A01:2021-Broken Access Control
- **Author**: KarsaSec Team
- **Version**: 1.0
- **Target Languages**: LanguageEnum.PHP
- **Tags**: csrf, wordpress, wp_ajax

## Description
Registering AJAX actions without wp_verify_nonce() or check_admin_referer() leaves endpoint susceptible to CSRF.

## Remediation Strategy
Verify nonces using wp_verify_nonce($_REQUEST['_wpnonce'], 'action_name') at the start of AJAX handlers.

## External References
- [https://cwe.mitre.org/data/definitions/352.html](https://cwe.mitre.org/data/definitions/352.html)
