"""Batch C9 URL Security Golden Corpus Qualification Test Suite (150 Fixtures across 7 Languages)."""

import pytest

from karsasec.analysis.url_security.engine import URLSecurityReasoningEngine
from karsasec.analysis.url_security.models import URLSecurityContext

LANGUAGES = ["python", "javascript", "php", "java", "go", "ruby", "dotnet"]

# --- 150 High-Quality Parametrized Fixtures ---

OPEN_REDIRECT_POSITIVES = [
    URLSecurityContext(
        source_kind="HTTP_REQUEST",
        source_symbol=f"next_url_{i}",
        raw_url=f"https://evil{i}.com/phishing",
        sink="redirect",
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 31)
]

SAFE_CONSTANT_AND_ALLOWLIST_NEGATIVES = [
    URLSecurityContext(
        source_kind="TRUSTED_CONSTANT" if i % 2 == 0 else "HTTP_REQUEST",
        source_symbol=f"safe_url_{i}",
        raw_url="/dashboard" if i % 2 == 0 else f"https://trusted{i}.com/home",
        sink="redirect",
        is_user_controlled=False if i % 2 == 0 else True,
        is_host_allowlisted=True if i % 2 != 0 else False,
        allowed_hosts=[f"trusted{i}.com"] if i % 2 != 0 else [],
        canonicalized_before_validation=True if i % 2 != 0 else None,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 51)
]

SCHEME_CONFUSION_FIXTURES = [
    URLSecurityContext(
        source_kind="HTTP_REQUEST",
        source_symbol=f"scheme_url_{i}",
        raw_url=f"javascript:alert({i})" if i % 2 == 0 else f"data:text/html,evil_{i}",
        sink="redirect",
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 16)
]

USERINFO_AUTHORITY_CONFUSION_FIXTURES = [
    URLSecurityContext(
        source_kind="HTTP_REQUEST",
        source_symbol=f"userinfo_url_{i}",
        raw_url=f"https://trusted.example@evil{i}.com/path",
        sink="redirect",
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 16)
]

BACKSLASH_CONFUSION_FIXTURES = [
    URLSecurityContext(
        source_kind="HTTP_REQUEST",
        source_symbol=f"backslash_url_{i}",
        raw_url=f"https://trusted.example\\@evil{i}.com/path" if i % 2 == 0 else f"\\\\evil{i}.com\\path",
        sink="redirect",
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 16)
]

OAUTH_WEAK_VALIDATION_FIXTURES = [
    URLSecurityContext(
        source_kind="OAUTH_PARAM",
        source_symbol=f"redirect_uri_{i}",
        raw_url=f"https://trusted.example.evil{i}.com/oauth/callback",
        sink="oauth_callback",
        validation_type="startswith",
        canonicalized_before_validation=True,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 16)
]

PASSWORD_RESET_POISONING_FIXTURES = [
    URLSecurityContext(
        source_kind="HOST_HEADER",
        source_symbol=f"host_hdr_{i}",
        raw_url=f"evil-attacker-{i}.com",
        sink="reset_url_gen",
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 11)
]


IDNA_CONFUSION_CORPUS = [
    URLSecurityContext(
        source_kind="HTTP_REQUEST",
        source_symbol=f"idna_url_{i}",
        raw_url=f"https://xn--e1afmkfd.xn--p1ai/path_{i}" if i % 2 == 0 else f"https://trusted.example.{i}/path",
        sink="redirect",
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 26)
]


@pytest.mark.parametrize("ctx", OPEN_REDIRECT_POSITIVES)
def test_open_redirect_positive_detection(ctx: URLSecurityContext) -> None:
    engine = URLSecurityReasoningEngine()
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", IDNA_CONFUSION_CORPUS)
def test_idna_confusion_corpus(ctx: URLSecurityContext) -> None:
    engine = URLSecurityReasoningEngine()
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", SAFE_CONSTANT_AND_ALLOWLIST_NEGATIVES)
def test_safe_constant_and_allowlist_negatives(ctx: URLSecurityContext) -> None:
    engine = URLSecurityReasoningEngine()
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


@pytest.mark.parametrize("ctx", SCHEME_CONFUSION_FIXTURES)
def test_scheme_confusion_fixtures(ctx: URLSecurityContext) -> None:
    engine = URLSecurityReasoningEngine()
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", USERINFO_AUTHORITY_CONFUSION_FIXTURES)
def test_userinfo_authority_confusion_fixtures(ctx: URLSecurityContext) -> None:
    engine = URLSecurityReasoningEngine()
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", BACKSLASH_CONFUSION_FIXTURES)
def test_backslash_confusion_fixtures(ctx: URLSecurityContext) -> None:
    engine = URLSecurityReasoningEngine()
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", OAUTH_WEAK_VALIDATION_FIXTURES)
def test_oauth_weak_validation_fixtures(ctx: URLSecurityContext) -> None:
    engine = URLSecurityReasoningEngine()
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


@pytest.mark.parametrize("ctx", PASSWORD_RESET_POISONING_FIXTURES)
def test_password_reset_poisoning_fixtures(ctx: URLSecurityContext) -> None:
    engine = URLSecurityReasoningEngine()
    ev = engine.evaluate_url_security(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_url_security_determinism() -> None:
    """Section Determinism: Verifies repeated evaluation yields 100% identical outputs."""
    engine = URLSecurityReasoningEngine()
    ctx = URLSecurityContext(
        source_kind="HTTP_REQUEST",
        source_symbol="next_path",
        raw_url="https://trusted.example@evil.example/",
        sink="redirect",
    )

    ev1 = engine.evaluate_url_security(ctx)
    ev2 = engine.evaluate_url_security(ctx)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()
