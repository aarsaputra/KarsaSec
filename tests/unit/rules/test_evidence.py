"""Unit tests for Evidence Framework components."""

from karsasec.parser.ast_nodes import ASTNode, Position
from karsasec.rules.enums import Confidence
from karsasec.rules.evidence import ConfidenceCalculator, EvidenceCollector
from karsasec.rules.schema import validate_rule_dict

def test_evidence_collector_and_calculator() -> None:
    rule_dict = {
        "rule": {"id": "KS-PY-0001"},
        "metadata": {"name": "SQL Injection", "author": "KarsaSec", "version": "2.0"},
        "match": {"language": "Python", "ast_node_types": ["call"]},
        "condition": {"symbol_triggers": ["cursor.execute"]},
        "evidence": {
            "require": ["user_input"],
            "score_weights": {"user_source": 40},
        },
        "output": {"severity": "HIGH", "confidence": "CONFIDENT", "message": "SQLi", "remediation": "Fix"},
    }
    rule = validate_rule_dict(rule_dict)

    node = ASTNode(
        node_id="node_1",
        parent_id=None,
        node_type="call",
        language="Python",
        file_path=None,
        byte_start=0,
        byte_end=20,
        start=Position(1, 0),
        end=Position(1, 20),
    )

    collector = EvidenceCollector()
    report = collector.collect(node, rule, matched_symbol="cursor.execute")

    assert report.total_score == 80  # 40 from sink + 40 from rule weights

    calc = ConfidenceCalculator()
    conf = calc.calculate(report, rule)
    assert conf == Confidence.CONFIDENT
