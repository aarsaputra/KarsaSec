"""Unit tests for YAMLRuleLoader and RuleCache."""

import pytest
from pathlib import Path
from karsasec.rules.loader import RuleCache, YAMLRuleLoader

def test_loader_valid_file(tmp_path: Path) -> None:
    rule_file = tmp_path / "test_rule.yaml"
    yaml_content = """
rule:
  id: KS-PY-0001
metadata:
  name: Test Rule
  author: KarsaSec
  version: "1.0"
  enabled: true
match:
  language: Python
  ast_node_types:
    - call
condition:
  symbol_triggers:
    - os.system
output:
  severity: HIGH
  confidence: CONFIDENT
  message: Test message.
  remediation: Test remediation.
"""
    rule_file.write_text(yaml_content, encoding="utf-8")

    cache = RuleCache()
    loader = YAMLRuleLoader(cache=cache)

    rule = loader.load_file(rule_file)
    assert rule.id == "KS-PY-0001"

    # Cache hit check
    cached_rule = cache.get(str(rule_file.resolve()))
    assert cached_rule is rule

def test_loader_invalid_yaml_syntax() -> None:
    invalid_yaml = "rule:\n  id: KS-PY-0001\n metadata: [invalid syntax"
    loader = YAMLRuleLoader()
    with pytest.raises(ValueError, match="Invalid YAML syntax"):
        loader.load_string(invalid_yaml)

def test_loader_directory_scan(tmp_path: Path) -> None:
    rule1 = tmp_path / "rule1.yaml"
    rule1.write_text("rule:\n  id: KS-PY-0001\nmatch:\n  language: Python\noutput:\n  severity: HIGH", encoding="utf-8")

    rule2 = tmp_path / "rule2.yml"
    rule2.write_text("rule:\n  id: KS-PY-0002\nmatch:\n  language: Python\noutput:\n  severity: LOW", encoding="utf-8")

    loader = YAMLRuleLoader()
    rules = loader.load_directory(tmp_path)
    assert len(rules) == 2
    rule_ids = [r.id for r in rules]
    assert "KS-PY-0001" in rule_ids
    assert "KS-PY-0002" in rule_ids
