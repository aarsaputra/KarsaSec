"""Unit tests for SourceResolver & Framework Wrapper Source Resolution (Phase 1).

Verifies:
1. Direct HTTP request source matching across Java, Python, PHP, Go, JS
2. Wrapper request source resolution (e.g. wrapper.getParameter, customRequest.getInput)
3. Delegation provenance tracking
4. Preservation of UNKNOWN state for unproven custom wrappers
"""

from karsasec.analysis.taint.sources import SourceCategory, SourceRegistry, SourceResolver


def test_source_resolver_direct_and_wrapper() -> None:
    resolver = SourceResolver()

    # Direct Java Servlet source
    sem1 = resolver.resolve_source("request.getParameter('id')", "Java")
    assert sem1 is not None
    assert sem1.category == SourceCategory.DIRECT
    assert sem1.framework == "Java Servlet"

    # Wrapper Java source
    sem2 = resolver.resolve_source("customRequest.getInput('id')", "Java")
    assert sem2 is not None
    assert sem2.category == SourceCategory.WRAPPER
    assert sem2.framework == "CustomWrapper"

    # Non-HTTP getter -> returns non-user-controlled semantics
    sem3 = resolver.resolve_source("config.getInternalSetting()", "Java")
    assert sem3 is not None and not sem3.is_user_controlled

    # Unproven getter -> returns None (UNKNOWN provenance)
    sem4 = resolver.resolve_source("unprovenObj.getInternalSetting()", "Java")
    assert sem4 is None


def test_source_registry_integration() -> None:
    reg = SourceRegistry()
    assert reg.is_source("request.getParameter('user')", "Java") is True
    assert reg.is_source("customRequest.getInput('data')", "Java") is True
    assert reg.is_source("req.body.id", "JavaScript") is True
    assert reg.is_source("request.args.get('q')", "Python") is True
    assert reg.is_source("internalUtility.compute()", "Python") is False
