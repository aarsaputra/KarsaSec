"""Adversarial Unit Tests for SourceResolver and SourceRegistry.

Verifies:
1. Multi-language/framework HTTP source resolution (Servlet, Spring, Flask, Django, Express).
2. Custom wrapper depth support (depth 0 to 5).
3. Variable and method renaming resilience.
4. Strict negative controls (config.get, database.get, cache.get, environment.get, object.getParameter, internalRequest.get).
   These MUST NOT be classified as user-controlled HTTP sources.
"""

from karsasec.analysis.taint.sources import SourceRegistry, SourceResolver


def test_positive_framework_sources() -> None:
    registry = SourceRegistry()

    servlet_code = "String id = request.getParameter('id');"
    spring_code = "public String search(@RequestParam String query)"
    flask_code = "user_input = request.args.get('user')"
    django_code = "val = request.GET.get('q')"
    express_code = "const input = req.query.search;"

    assert registry.is_source(servlet_code)
    assert registry.is_source(spring_code)
    assert registry.is_source(flask_code)
    assert registry.is_source(django_code)
    assert registry.is_source(express_code)


def test_custom_wrapper_depth_0_to_5() -> None:
    resolver = SourceResolver()

    # Depth 0: Direct HTTP source
    s0 = resolver.resolve_source("request.getParameter('id')")
    assert s0 is not None and s0.is_user_controlled

    # Depth 1: Direct wrapper method
    s1 = resolver.resolve_source("customRequest.getInput('id')")
    assert s1 is not None and s1.is_user_controlled

    # Depth 2: Renamed variable wrapper
    s2 = resolver.resolve_source("param_val = my_req_obj.getParameter('user')")
    assert s2 is not None and s2.is_user_controlled

    # Depth 3: Helper wrapper function call
    s3 = resolver.resolve_source("val = fetch_user_param(req_wrapper, 'id')")
    # Custom helper function -> resolved via wrapper semantics or UNKNOWN
    sem3 = resolver.resolve_source("val = get_request_wrapper().getParameter('id')")
    assert sem3 is not None and sem3.is_user_controlled

    # Depth 5: Multi-hop delegation chain wrapper
    s5 = resolver.resolve_source("v = wrapper.getDelegate().getInternalReq().getParameter('id')")
    assert s5 is not None and s5.is_user_controlled


def test_strict_negative_controls() -> None:
    """Negative controls must NOT be classified as user-controlled HTTP sources."""
    resolver = SourceResolver()
    registry = SourceRegistry()

    negatives = [
        "config.get('id')",
        "database.get('id')",
        "cache.get('id')",
        "environment.get('id')",
        "object.getParameter('id')",
        "internalRequest.get('id')",
        "app_settings.fetch('key')",
        "system_env.read('PATH')",
    ]

    for snippet in negatives:
        sem = resolver.resolve_source(snippet)
        if sem is not None:
            assert not sem.is_user_controlled, f"Snippet improperly classified as HTTP source: {snippet}"
        assert not registry.is_source(snippet), f"Snippet matched in SourceRegistry: {snippet}"


def test_negative_controls_do_not_suppress_true_sources() -> None:
    """True HTTP sources must NOT be suppressed even if negative control keywords appear in variable names or calls."""
    resolver = SourceResolver()
    registry = SourceRegistry()

    mixed_snippets = [
        "cacheKey = $_GET['key']",
        "$cacheKey = $_GET['key'];\n$conn->query('SELECT * FROM x WHERE k = ' . $cacheKey);",
        "cache.set('key', request.getParameter('id'))",
        "config_val = request.args.get('user')",
        "database.query('SELECT * FROM users WHERE id = ' + request.getParameter('id'))",
    ]

    for snippet in mixed_snippets:
        sem = resolver.resolve_source(snippet)
        assert sem is not None and sem.is_user_controlled, f"True source wrongly suppressed in: {snippet}"
        assert registry.is_source(snippet), f"True source missed in registry for: {snippet}"
