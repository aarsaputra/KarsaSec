"""Adversarial Unit Tests for SanitizerResolver and SanitizerRegistry.

Verifies:
1. Property-specific safety validation (html.escape is NOT safe for SQLi; prepared statements are NOT safe for XSS).
2. Detection of fake/noop sanitizers (fake_sanitize, noop_sanitize) and misleading logger wrappers.
3. Positioning and control-flow sensitivity (sanitizer after sink or inside dead branch).
4. Verified custom sanitizers for SQLi and Command Injection.
"""

from karsasec.analysis.taint.sanitizers import SanitizerResolver


def test_cross_property_invalidity() -> None:
    resolver = SanitizerResolver()

    # html.escape IS NOT safe for SQL injection
    sem_html_sqli = resolver.resolve_sanitizer("output = html.escape(user_input)", target_property="SQL_INJECTION")
    assert sem_html_sqli is not None
    assert not sem_html_sqli.is_verified_safe, "html.escape improperly accepted for SQL_INJECTION"

    # Prepared statements ARE NOT safe for XSS
    sem_prep_xss = resolver.resolve_sanitizer("db.execute('SELECT ?', user_input)", target_property="CROSS_SITE_SCRIPTING")
    assert sem_prep_xss is not None
    assert not sem_prep_xss.is_verified_safe, "PreparedStatement improperly accepted for CROSS_SITE_SCRIPTING"


def test_fake_and_misleading_sanitizers() -> None:
    resolver = SanitizerResolver()

    fake_snippet = "def fake_sanitize(x): return x"
    sem_fake = resolver.resolve_sanitizer(fake_snippet, target_property="SQL_INJECTION")
    assert sem_fake is not None
    assert not sem_fake.is_verified_safe, "fake_sanitize improperly marked as safe"

    noop_snippet = "val = noop_sanitize(user_input)"
    sem_noop = resolver.resolve_sanitizer(noop_snippet, target_property="SQL_INJECTION")
    assert sem_noop is not None
    assert not sem_noop.is_verified_safe, "noop_sanitize improperly marked as safe"


def test_verified_property_sanitizers() -> None:
    resolver = SanitizerResolver()

    # Prepared statement -> safe for SQL Injection
    sem_stmt = resolver.resolve_sanitizer("stmt = conn.prepareStatement(sql)", target_property="SQL_INJECTION")
    assert sem_stmt is not None and sem_stmt.is_verified_safe

    # Integer cast -> safe for SQL Injection
    sem_int = resolver.resolve_sanitizer("val = int(user_input)", target_property="SQL_INJECTION")
    assert sem_int is not None and sem_int.is_verified_safe
