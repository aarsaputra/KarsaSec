"""Unit tests verifying Rule Collision Detection (INV-G5.4-06)."""

from karsasec.benchmark.rule_collision import detect_rule_collisions


def test_rule_collision_duplicate_id() -> None:
    existing = [{"rule_id": "KS-PHP-0002", "cwe": "CWE-89"}]
    new_rules = [{"rule_id": "KS-PHP-0002", "cwe": "CWE-89"}]
    res = detect_rule_collisions(existing, new_rules)
    assert res["status"] == "COLLISION_DETECTED"
    assert res["collisions"][0]["collision_type"] == "DUPLICATE_ID"
    assert res["collisions"][0]["action"] == "BLOCK"


def test_rule_collision_sanitizer_conflict() -> None:
    existing = [{"rule_id": "R_01", "cwe": "CWE-89", "source_pattern": "s1", "property": "SQLi", "sanitizer_semantics": "ESCAPED"}]
    new_rules = [{"rule_id": "R_02", "cwe": "CWE-78", "source_pattern": "s2", "property": "SQLi", "sanitizer_semantics": "STRIPPED"}]
    res = detect_rule_collisions(existing, new_rules)
    assert res["status"] == "COLLISION_DETECTED"
    assert res["collisions"][0]["collision_type"] == "SANITIZER_CONFLICT"


def test_rule_collision_pass_on_clean() -> None:
    existing = [{"rule_id": "R_01", "cwe": "CWE-89", "source_pattern": "p1", "sink_pattern": "s1"}]
    new_rules = [{"rule_id": "R_K1_01", "cwe": "CWE-347", "source_pattern": "p2", "sink_pattern": "s2"}]
    res = detect_rule_collisions(existing, new_rules)
    assert res["status"] == "PASS"
    assert res["has_collisions"] is False
