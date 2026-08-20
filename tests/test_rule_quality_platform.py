from __future__ import annotations

from typer.testing import CliRunner

from karsasec.cli.main import app
from karsasec.quality.conflicts import ConflictDetector
from karsasec.quality.coverage import CoverageAnalyzer
from karsasec.quality.dead_code import DeadCodeDetector
from karsasec.quality.profiler import RuleProfiler

runner = CliRunner()


def test_coverage_analyzer() -> None:
    analyzer = CoverageAnalyzer()
    res = analyzer.analyze()
    assert res["total_rules"] >= 120
    assert "Go" in res["languages"]
    assert "PHP" in res["languages"]


def test_rule_profiler() -> None:
    profiler = RuleProfiler()
    results = profiler.profile_execution()
    assert len(results) >= 120
    assert "elapsed_ms" in results[0]


def test_conflict_detector() -> None:
    detector = ConflictDetector()
    report = detector.detect_conflicts()
    assert isinstance(report["duplicate_names"], list)
    assert isinstance(report["pattern_overlaps"], list)


def test_dead_code_detector() -> None:
    detector = DeadCodeDetector()
    issues = detector.detect_dead_rules()
    assert len(issues) == 0


def test_rules_quality_cli_subcommands() -> None:
    res_prof = runner.invoke(app, ["rules", "profile"])
    assert res_prof.exit_code == 0
    assert "Rule Performance Profile" in res_prof.output

    res_conf = runner.invoke(app, ["rules", "conflicts"])
    assert res_conf.exit_code == 0
    assert "Conflict & Overlap Report" in res_conf.output

    res_dead = runner.invoke(app, ["rules", "dead-code"])
    assert res_dead.exit_code == 0
    assert "Rule Dead Code Report" in res_dead.output
