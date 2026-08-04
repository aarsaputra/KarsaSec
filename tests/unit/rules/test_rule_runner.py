"""Unit test for RuleTestRunner."""

from pathlib import Path
from karsasec.rules.enums import Confidence, Severity
from karsasec.rules.schema import validate_rule_dict
from karsasec.rules.testing import RuleTestCase, RuleTestRunner

def test_rule_runner_with_sample_files(tmp_path: Path) -> None:
    rule_dict = {
        "rule": {"id": "KS-PY-0001"},
        "metadata": {"name": "Eval Injection", "author": "KarsaSec", "version": "1.0"},
        "match": {"language": "Python", "ast_node_types": ["call"]},
        "condition": {"symbol_triggers": ["eval"]},
        "output": {"severity": "HIGH", "confidence": "CONFIDENT", "message": "Eval used", "remediation": "Fix"},
    }
    rule = validate_rule_dict(rule_dict)

    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("eval(user_input)\n", encoding="utf-8")

    safe_file = tmp_path / "safe.py"
    safe_file.write_text("print('hello world')\n", encoding="utf-8")

    case = RuleTestCase(
        rule_id=rule.id,
        vulnerable_files=[vuln_file],
        safe_files=[safe_file],
    )

    runner = RuleTestRunner()
    report = runner.run_case(rule, case)

    assert report.passed is True
    assert report.vulnerable_passed is True
    assert report.safe_passed is True
    assert report.vulnerable_findings_count == 1
    assert report.safe_findings_count == 0
