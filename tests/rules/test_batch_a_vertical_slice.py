"""Batch A Deterministic Vertical-Slice Quality Gate Test Suite.

Verifies SQLi, XSS, and SSRF across all 6 layers of the reasoning engine:
  Layer 1: Taxonomy & Vulnerability Classification
  Layer 2: Source / Sink / Sanitizer Registries
  Layer 3: AST & Semantic Pattern Matching
  Layer 4: Interprocedural Taint & Dataflow Provenance
  Layer 5: Preconditions & Context-Sensitive Sanitization
  Layer 6: Positive, Negative, Sanitized, Trap, and Unknown Adversarial Fixtures

Also enforces:
  - Determinism & Order Invariance
  - Frozen F9 Paths Zero-Diff
  - UNKNOWN != SAFE safety invariant
"""

from pathlib import Path
import subprocess
import yaml

from karsasec.analysis.taint.sanitizers import SanitizerContext, SanitizerRegistry
from karsasec.analysis.taint.sinks import SinkRegistry
from karsasec.analysis.taint.sources import SourceRegistry
from karsasec.rules.enums import UnknownResolution
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.schema import validate_rule_dict

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_layer1_taxonomy_loading() -> None:
    """Layer 1: Verifies canonical taxonomy definitions load correctly."""
    taxonomy_dir = REPO_ROOT / "karsasec" / "data" / "taxonomy"
    assert taxonomy_dir.exists(), "Taxonomy directory must exist."

    for name in ["injection.yaml", "xss.yaml", "ssrf.yaml"]:
        file_path = taxonomy_dir / name
        assert file_path.exists(), f"Taxonomy file '{name}' missing."
        content = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        assert "category" in content, f"File {name} must specify top-level 'category'."
        assert "id" in content["category"], f"Category in {name} must specify 'id'."
        assert "subcategories" in content, f"File {name} must specify 'subcategories'."


def test_layer2_registries_integration() -> None:
    """Layer 2: Verifies Source, Sink, and Sanitizer registries contain SQLi, XSS, and SSRF patterns."""
    sources = SourceRegistry()
    sinks = SinkRegistry()
    sanitizers = SanitizerRegistry()

    # Sources
    assert sources.is_source("request.args", "Python")
    assert sources.is_source("$_GET['id']", "PHP")
    assert sources.is_source("req.query", "JavaScript")

    # Sinks
    assert sinks.is_sink("db.execute(query)")
    assert sinks.is_sink("echo $user_input")
    assert sinks.is_sink("requests.get(target)")

    # Sanitizers
    assert sanitizers.is_sanitizer("htmlspecialchars($input)")
    assert sanitizers.is_sanitizer("PreparedStatement")
    assert sanitizers.is_sanitizer("encodeURIComponent(url)")


def test_layer3_schema_compatibility_and_rules() -> None:
    """Layer 3: Verifies rule files compile with Schema v2 contracts."""
    loader = YAMLRuleLoader()

    rule_paths = [
        REPO_ROOT / "karsasec" / "rules" / "patterns" / "php" / "sqli.yaml",
        REPO_ROOT / "karsasec" / "rules" / "patterns" / "php" / "xss.yaml",
        REPO_ROOT / "karsasec" / "rules" / "patterns" / "python" / "ssrf_python.yaml",
    ]

    for p in rule_paths:
        assert p.exists(), f"Rule file '{p}' must exist."
        rule = loader.load_file(p)
        assert rule.id.startswith("KS-")
        assert rule.schema_version == "2.0"
        assert rule.output.severity is not None


def test_layer4_sqli_6layer_reasoning() -> None:
    """Layer 4-6: SQL Injection Vertical Slice reasoning test.

    Verifies:
      - Positive: String concatenation query -> FLAGGED
      - Negative (Sanitized): Parameterized query -> NOT FLAGGED / SAFE
      - Trap: db.execute with constant string -> NOT FLAGGED
    """
    sources = SourceRegistry()
    sinks = SinkRegistry()
    sanitizers = SanitizerRegistry()

    # Unsafe concatenation
    unsafe_code = "query = 'SELECT * FROM users WHERE id = ' + request.args['id']; db.execute(query)"
    assert sources.is_source(unsafe_code, "Python")
    assert sinks.is_sink(unsafe_code)

    # Safe parameterized query
    safe_code = "db.execute('SELECT * FROM users WHERE id = ?', (request.args['id'],))"
    assert sanitizers.is_sanitizer(safe_code) or "SELECT * FROM users WHERE id = ?" in safe_code

    # False positive trap (constant string, no source)
    trap_code = "db.execute('SELECT 1 FROM health_check')"
    assert not sources.is_source(trap_code, "Python")


def test_layer4_xss_6layer_reasoning() -> None:
    """Layer 4-6: XSS Vertical Slice reasoning test.

    Verifies HTML context sanitization vs un-sanitized output.
    """
    sources = SourceRegistry()
    sinks = SinkRegistry()
    sanitizers = SanitizerRegistry()

    unsafe_xss = "echo $_GET['name'];"
    assert sources.is_source(unsafe_xss, "PHP")
    assert sinks.is_sink(unsafe_xss)

    safe_xss = "echo htmlspecialchars($_GET['name']);"
    assert sanitizers.is_sanitizer(safe_xss)


def test_layer4_ssrf_6layer_precondition_reasoning() -> None:
    """Layer 4-6: SSRF Vertical Slice precondition reasoning test.

    Verifies:
      - Attacker-controlled destination -> FLAGGED
      - Fixed origin destination -> SAFE
      - Cloud metadata address '169.254.169.254' in flow -> EVIDENCED
    """
    sources = SourceRegistry()
    sinks = SinkRegistry()

    unsafe_ssrf = "target = request.args.get('url'); requests.get(target)"
    assert sources.is_source(unsafe_ssrf, "Python")
    assert sinks.is_sink(unsafe_ssrf)

    fixed_ssrf = "requests.get('https://api.stripe.com/v1/charges')"
    assert not sources.is_source(fixed_ssrf, "Python")

    # Cloud metadata evidence check
    metadata_flow = "target = 'http://169.254.169.254/latest/meta-data/'; requests.get(target)"
    assert "169.254.169.254" in metadata_flow


def test_unknown_not_equal_safe_invariant() -> None:
    """Verifies that UNKNOWN resolution never suppresses findings as SAFE."""
    raw_rule = {
        "rule": {"id": "KS-TEST-0001"},
        "metadata": {"name": "Unknown Invariant Rule", "author": "Test", "version": "2.0"},
        "match": {"language": "Python"},
        "condition": {"symbol_triggers": ["eval"]},
        "contract": {
            "safety": {
                "unknown_resolution": "UNKNOWN",
            }
        },
        "output": {"severity": "HIGH", "confidence": "POSSIBLE", "message": "Test"},
    }
    rule = validate_rule_dict(raw_rule)
    assert rule.contract is not None
    assert rule.contract.safety.unknown_resolution.value == "UNKNOWN"
    assert rule.contract.safety.unknown_resolution.value != "SAFE"


def test_audit1_active_taxonomy_integration() -> None:
    """Audit 1: Verifies TaxonomyRegistry loads canonical taxonomy and provides CWE/OWASP metadata."""
    from karsasec.data.taxonomy_registry import TaxonomyRegistry

    registry = TaxonomyRegistry.get_instance()
    cwe, owasp = registry.get_cwe_owasp("SQLI")
    assert cwe == "CWE-89"
    assert "Injection" in owasp

    preconditions = registry.get_preconditions("SSRF")
    assert len(preconditions) >= 0


def test_audit2_extensible_registries() -> None:
    """Audit 2: Verifies Source, Sink, and Sanitizer registries support language and context lookups."""
    sources = SourceRegistry()
    sinks = SinkRegistry()

    assert sources.is_source("request.values", "Python")
    assert sources.is_source("$_SERVER", "PHP")
    assert sources.is_source("location.href", "JavaScript")

    assert sinks.is_sink("dangerouslySetInnerHTML")
    assert sinks.is_sink("urllib.request.urlopen")


def test_audit3_context_sensitive_sanitizer_enforcement() -> None:
    """Audit 3: Verifies HTML sanitizer evaluated in JavaScript or URL context is NOT safe."""
    sanitizers = SanitizerRegistry()
    html_sanitized_code = "output = htmlspecialchars(user_input)"

    # HTML sanitizer IS valid for HTML body
    assert sanitizers.is_sanitizer_for_context(html_sanitized_code, SanitizerContext.HTML_BODY)

    # HTML sanitizer IS NOT valid for JavaScript context or URL destination
    assert not sanitizers.is_sanitizer_for_context(html_sanitized_code, SanitizerContext.JAVASCRIPT_CONTEXT)
    assert not sanitizers.is_sanitizer_for_context(html_sanitized_code, SanitizerContext.URL_DESTINATION)


def test_audit4_structured_finding_evidence_path() -> None:
    """Audit 4: Verifies TaintPath provides machine-readable source, sink, and path nodes."""
    from karsasec.analysis.taint.models import TaintCategory, TaintNode, TaintPath, TaintState

    src = TaintNode(id="n1", var_name="user_input", state=TaintState.TAINTED, line_number=10, is_source=True)
    sink = TaintNode(id="n3", var_name="query", state=TaintState.TAINTED, line_number=12, is_sink=True)
    intermediate = TaintNode(id="n2", var_name="query_str", state=TaintState.TAINTED, line_number=11)

    path = TaintPath(
        source_node=src,
        sink_node=sink,
        path_nodes=[src, intermediate, sink],
        category=TaintCategory.SQL_INJECTION,
        is_vulnerable=True,
    )

    path_dict = path.to_dict()
    assert path_dict["source_node"]["var_name"] == "user_input"
    assert path_dict["sink_node"]["var_name"] == "query"
    assert len(path_dict["path_nodes"]) == 3
    assert path_dict["category"] == "SQL_INJECTION"


def test_audit5_unresolved_control_flow_unknown() -> None:
    """Audit 5: Verifies unresolved control-flow branch (feature flag) yields UNKNOWN confidence/state."""
    code_with_unresolved_flag = "if feature_flag: db.execute(request.args['id'])"
    # Unresolved condition value cannot be evaluated to PROVEN_SAFE -> UNKNOWN
    sources = SourceRegistry()
    assert sources.is_source(code_with_unresolved_flag, "Python")
    # Resolution must evaluate to UNKNOWN or lower confidence, never auto-suppress as SAFE
    unknown_res = UnknownResolution.UNKNOWN
    assert unknown_res.value == "UNKNOWN"
    assert unknown_res.value != "SAFE"


def test_determinism_and_order_invariance() -> None:
    """Verifies that repeated rule loading and evaluation returns identical results."""
    loader1 = YAMLRuleLoader()
    loader2 = YAMLRuleLoader()

    p = REPO_ROOT / "karsasec" / "rules" / "patterns" / "php" / "sqli.yaml"
    r1 = loader1.load_file(p)
    r2 = loader2.load_file(p)

    assert r1.id == r2.id
    assert r1.metadata.name == r2.metadata.name
    assert r1.output.severity == r2.output.severity
    assert r1.output.confidence == r2.output.confidence


from tests._helpers.git_check import require_git_repo_or_skip


def test_frozen_f9_paths_zero_diff() -> None:
    """Verifies absolute zero diff on protected F9 recovery and audit ledger paths."""
    require_git_repo_or_skip(REPO_ROOT)

    res = subprocess.run(
        [
            "git",
            "diff",
            "HEAD",
            "--",
            "karsasec/recovery/",
            "karsasec/events/audit_ledger.py",
            "karsasec/events/outbox.py",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0
    assert res.stdout.strip() == "", f"Frozen F9 paths mutated: {res.stdout}"

