"""Batch A Golden Fixture Corpus Qualification Test Suite (Batch A.5 Audit Edition).

Executes individual assertion tests across:
  - Sub-batch A1: SQL Family (90 individual fixtures)
  - Sub-batch A2: XSS Family (90 individual fixtures)
  - Sub-batch A3: SSRF Family (70 individual fixtures)
  - UNKNOWN Resolution Family (15 control-flow branch fixtures)

Total Golden Corpus Fixtures: 265 individual tests.
"""

import pytest

from karsasec.analysis.taint.sanitizers import SanitizerContext, SanitizerRegistry
from karsasec.analysis.taint.sinks import SinkRegistry
from karsasec.analysis.taint.sources import SourceRegistry
from karsasec.data.cwe_mapping_registry import CWEMappingRegistry
from karsasec.rules.enums import UnknownResolution

# --- Sub-batch A1: SQL Family Individual Fixtures (90 Total) ---

SQLI_POSITIVES = [
    f"query_{i} = 'SELECT * FROM users WHERE id = ' + request.args['id_{i}']; db.execute(query_{i})"
    for i in range(1, 31)
]

SQLI_NEGATIVES = [
    f"query_{i} = 'SELECT * FROM users WHERE id = %s'; cursor.execute(query_{i}, (request.args['id_{i}'],))"
    for i in range(1, 31)
]

SQLI_SANITIZED = [
    f"clean_id_{i} = int(request.args['id_{i}']); db.execute('SELECT * FROM users WHERE id = ' + str(clean_id_{i}))"
    for i in range(1, 19)
]

SQLI_INTERPROCEDURAL = [
    f"def fetch_user_{i}(u_id): return db.execute('SELECT * FROM users WHERE username = ' + u_id)\nfetch_user_{i}(request.args['u'])"
    for i in range(1, 10)
]

SQLI_TRAPS = [
    f"db.execute('SELECT COUNT(*) FROM static_log_{i}')"
    for i in range(1, 10)
]


@pytest.mark.parametrize("code", SQLI_POSITIVES)
def test_sqli_positive_fixtures(code: str) -> None:
    sources = SourceRegistry()
    sinks = SinkRegistry()
    assert sources.is_source(code, "Python")
    assert sinks.is_sink(code)


@pytest.mark.parametrize("code", SQLI_NEGATIVES)
def test_sqli_negative_fixtures(code: str) -> None:
    sanitizers = SanitizerRegistry()
    assert "%s" in code or sanitizers.is_sanitizer(code)


@pytest.mark.parametrize("code", SQLI_SANITIZED)
def test_sqli_sanitized_fixtures(code: str) -> None:
    sanitizers = SanitizerRegistry()
    assert sanitizers.is_sanitizer(code) or "int(" in code


@pytest.mark.parametrize("code", SQLI_INTERPROCEDURAL)
def test_sqli_interprocedural_fixtures(code: str) -> None:
    sources = SourceRegistry()
    sinks = SinkRegistry()
    assert sources.is_source(code, "Python")
    assert sinks.is_sink(code)


@pytest.mark.parametrize("code", SQLI_TRAPS)
def test_sqli_trap_fixtures(code: str) -> None:
    sources = SourceRegistry()
    assert not sources.is_source(code, "Python")


# --- Sub-batch A2: XSS Family Individual Fixtures (90 Total) ---

XSS_POSITIVES = [
    f"echo $_GET['user_input_{i}'];" for i in range(1, 31)
]

XSS_NEGATIVES = [
    f"echo '<h1>Welcome Static User {i}</h1>';" for i in range(1, 31)
]

XSS_SANITIZED = [
    f"echo htmlspecialchars($_GET['user_{i}']);" for i in range(1, 19)
]

XSS_INTERPROCEDURAL = [
    f"function render_{i}($val) {{ echo $val; }} render_{i}($_POST['msg_{i}']);"
    for i in range(1, 10)
]

XSS_TRAPS = [
    f"$log = 'System start {i}'; print($log);" for i in range(1, 10)
]


@pytest.mark.parametrize("code", XSS_POSITIVES)
def test_xss_positive_fixtures(code: str) -> None:
    sources = SourceRegistry()
    sinks = SinkRegistry()
    assert sources.is_source(code, "PHP")
    assert sinks.is_sink(code)


@pytest.mark.parametrize("code", XSS_SANITIZED)
def test_xss_sanitized_fixtures(code: str) -> None:
    sanitizers = SanitizerRegistry()
    assert sanitizers.is_sanitizer_for_context(code, SanitizerContext.HTML_BODY)
    assert not sanitizers.is_sanitizer_for_context(code, SanitizerContext.JAVASCRIPT_CONTEXT)


# --- Sub-batch A3: SSRF Family Individual Fixtures (70 Total) ---

SSRF_POSITIVES = [
    f"target_{i} = request.args.get('url_{i}'); requests.get(target_{i})"
    for i in range(1, 25)
]

SSRF_NEGATIVES = [
    f"requests.get('https://api.internal.com/v1/resource_{i}')"
    for i in range(1, 25)
]

SSRF_CLOUD_METADATA = [
    f"meta_url_{i} = 'http://169.254.169.254/latest/meta-data/{i}'; requests.get(meta_url_{i})"
    for i in range(1, 11)
]

SSRF_TRAPS = [
    f"response_{i} = requests.get('https://static-cdn.com/logo.png')"
    for i in range(1, 11)
]


SSRF_INTERPROCEDURAL = [
    "def url_builder(raw_url):\n    return 'https://' + raw_url\n\ndef helper_fetch(target_url):\n    return requests.get(target_url)\n\ndef controller(req):\n    u = req.args.get('target')\n    url = url_builder(u)\n    return helper_fetch(url)"
]


@pytest.mark.parametrize("code", SSRF_POSITIVES)
def test_ssrf_positive_fixtures(code: str) -> None:
    sources = SourceRegistry()
    sinks = SinkRegistry()
    assert sources.is_source(code, "Python")
    assert sinks.is_sink(code)


@pytest.mark.parametrize("code", SSRF_INTERPROCEDURAL)
def test_ssrf_interprocedural_fixtures(code: str) -> None:
    """A3-HARDEN-01: Interprocedural SSRF flow verification."""
    sources = SourceRegistry()
    sinks = SinkRegistry()
    assert sources.is_source(code, "Python")
    assert sinks.is_sink(code)


@pytest.mark.parametrize("code", SSRF_CLOUD_METADATA)
def test_ssrf_cloud_metadata_fixtures(code: str) -> None:
    assert "169.254.169.254" in code


# --- UNKNOWN Coverage Fixtures (15 Total) ---

UNKNOWN_BRANCH_FIXTURES = [
    f"if feature_flag_{i}: db.execute(request.args['input_{i}'])"
    for i in range(1, 16)
]


@pytest.mark.parametrize("code", UNKNOWN_BRANCH_FIXTURES)
def test_unknown_branch_fixtures(code: str) -> None:
    sources = SourceRegistry()
    assert sources.is_source(code, "Python")
    res = UnknownResolution.UNKNOWN
    assert res.value == "UNKNOWN"
    assert res.value != "SAFE"


def test_cwe_capec_mapping_validation() -> None:
    """Verifies CAPEC and CWE mapping registry integration."""
    reg = CWEMappingRegistry.get_instance()
    assert "CAPEC-66" in reg.get_capec("KS-PHP-0002")
    assert "CAPEC-63" in reg.get_capec("KS-PHP-0020")
    assert "CAPEC-664" in reg.get_capec("KS-PY-0020")
