"""Automated security corpus benchmark runner for quantitative evaluation of rules precision and recall."""

from pathlib import Path
from typing import Any

import yaml

from karsasec.cli.commands.scan import scan_file_task
from karsasec.core.execution import rule_executor
from karsasec.eval.metrics import EvaluationMetrics
from karsasec.parser.target_detector import TargetDetector
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.patterns import get_default_rules_directory


class BenchmarkEvaluator:
    """Evaluates rule accuracy against security corpus datasets (vulnerable, safe, regression)."""

    def __init__(self, corpus_root: Path | None = None, rules_dir: Path | None = None):
        self.corpus_root = corpus_root or Path(__file__).resolve().parents[2] / "security_corpus"
        self.rules_dir = rules_dir or get_default_rules_directory()
        self.loader = YAMLRuleLoader()
        self.target_detector = TargetDetector()

    def evaluate(self) -> EvaluationMetrics:
        """Run benchmark evaluation over security_corpus files matching rule specifications."""
        rules = self.loader.load_directory(self.rules_dir)
        tp = 0
        fp = 0
        fn = 0
        tn = 0

        if not self.corpus_root.exists():
            return EvaluationMetrics(0, 0, 0, 0, 0)

        category_dirs: list[Path] = []
        for path in self.corpus_root.rglob("*"):
            if path.is_dir() and any((path / sub).exists() for sub in ("vulnerable", "safe", "regression")):
                if path not in category_dirs:
                    category_dirs.append(path)

        for category_dir in sorted(category_dirs):
            metadata_file = category_dir / "metadata.yaml"
            if not metadata_file.exists():
                metadata_file = category_dir.parent / "metadata.yaml"

            target_rule_ids: set[str] = set()
            if metadata_file.exists():
                try:
                    meta = yaml.safe_load(metadata_file.read_text(encoding="utf-8")) or {}
                    if "rule_id" in meta and meta["rule_id"]:
                        target_rule_ids.add(meta["rule_id"])
                    if "rules" in meta and isinstance(meta["rules"], list):
                        for r in meta["rules"]:
                            if isinstance(r, dict) and "rule_id" in r:
                                target_rule_ids.add(r["rule_id"])
                except Exception:
                    pass

            def file_has_target_finding(findings_list: list[Any], target_ids: set[str]) -> bool:
                if not findings_list:
                    return False
                if not target_ids:
                    return len(findings_list) > 0
                return any(f.rule_id in target_ids for f in findings_list)

            # 1. Positive samples (vulnerable and regression files must trigger findings)
            for sub in ("vulnerable", "regression"):
                sub_dir = category_dir / sub
                if sub_dir.exists():
                    for v_file in sub_dir.rglob("*"):
                        if v_file.is_file() and not v_file.name.startswith("."):
                            findings, _, _, _ = scan_file_task(
                                v_file, self.target_detector, rule_executor, rules, []
                            )
                            if file_has_target_finding(findings, target_rule_ids):
                                tp += 1
                            else:
                                fn += 1

            # 2. Negative samples (safe files must NOT trigger findings)
            safe_dir = category_dir / "safe"
            if safe_dir.exists():
                for s_file in safe_dir.rglob("*"):
                    if s_file.is_file() and not s_file.name.startswith("."):
                        findings, _, _, _ = scan_file_task(
                            s_file, self.target_detector, rule_executor, rules, []
                        )
                        if file_has_target_finding(findings, target_rule_ids):
                            fp += 1
                        else:
                            tn += 1

        total = tp + fp + fn + tn
        return EvaluationMetrics(
            total_samples=total,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=tn,
        )
