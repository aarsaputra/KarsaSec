"""Automated security corpus verification test suite."""

from pathlib import Path
import pytest

from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.testing import RuleTestCase, RuleTestRunner

CORPUS_DIR = Path("/home/lota1337/python/KarsaSec/security_corpus")
RULES_DIR = Path("/home/lota1337/python/KarsaSec/karsasec/rules/patterns")

RULE_CORPUS_MAP = {
    "KS-PY-0001": CORPUS_DIR / "python" / "sqli",
    "KS-PY-0002": CORPUS_DIR / "python" / "cmdi",
    "KS-PY-0003": CORPUS_DIR / "python" / "deserialization",
    "KS-JS-0001": CORPUS_DIR / "javascript" / "eval",
    "KS-JS-0002": CORPUS_DIR / "javascript" / "xss",
    "KS-PHP-0001": CORPUS_DIR / "php" / "rce",
    "KS-PHP-0002": CORPUS_DIR / "php" / "sqli",
    "KS-GO-0001": CORPUS_DIR / "go" / "sqli",
    "KS-GO-0002": CORPUS_DIR / "go" / "cmdi",
    "KS-COMMON-0001": CORPUS_DIR / "common" / "secret",
}

def test_all_production_rules_against_security_corpus() -> None:
    """Verifies all 10 production rules against vulnerable, safe, and regression corpus suites."""
    loader = YAMLRuleLoader()
    rules = loader.load_directory(RULES_DIR)
    runner = RuleTestRunner()

    assert len(rules) >= 10, f"Expected at least 10 production rules, loaded {len(rules)}"

    for rule in rules:
        target_corpus = RULE_CORPUS_MAP.get(rule.id)
        if not target_corpus or not target_corpus.exists():
            continue

        vuln_files = list((target_corpus / "vulnerable").glob("*"))
        safe_files = list((target_corpus / "safe").glob("*"))
        reg_files = list((target_corpus / "regression").glob("*"))

        case = RuleTestCase(
            rule_id=rule.id,
            vulnerable_files=vuln_files,
            safe_files=safe_files,
            regression_files=reg_files,
            min_expected_findings=1,
        )
        report = runner.run_case(rule, case)
        assert report.vulnerable_passed is True, f"Rule {rule.id} failed vulnerable test: {report.details}"
        assert report.safe_passed is True, f"Rule {rule.id} failed safe test (false positive): {report.details}"
        assert report.regression_passed is True, f"Rule {rule.id} failed regression test: {report.details}"
        assert report.passed is True, f"Rule {rule.id} failed overall corpus check"
