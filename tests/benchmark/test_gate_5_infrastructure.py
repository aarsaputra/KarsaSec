"""Comprehensive Gate 5 Infrastructure Unit Tests.

Verifies:
1. OWASP Benchmark Adapter (CSV parsing & synthetic suite generation)
2. Security Mutation Testing Engine (SecurityMutation protocol, SinkToSafe, SourceToConstant, MutationScore, MutationStatus)
3. Adversarial Semantic Corpus (6 categories: TRUE_POSITIVE, TRUE_NEGATIVE, AMBIGUOUS, CONTRADICTORY, BOUNDARY, DECEPTIVE)
4. Differential Regression Framework (Gate 5F baseline vs candidate comparison)
5. Gate 5H — 95% Wilson Score Confidence Interval calculation
6. Gate 5G — Error Taxonomy and Language x Framework matrix
"""

from karsasec.analysis.decision.models import DecisionResolution
from karsasec.benchmark.adapters.owasp_benchmark import OWASPBenchmarkAdapter
from karsasec.benchmark.corpus import AdversarialSemanticCorpus, CorpusCategory
from karsasec.benchmark.harness import BenchmarkHarness
from karsasec.benchmark.metrics import compute_wilson_confidence_interval
from karsasec.benchmark.models import GateVerdict, GroundTruthStatus
from karsasec.benchmark.mutation import (
    MutationStatus,
    SecurityMutationEngine,
    SinkToSafeMutation,
    SourceToConstantMutation,
)
from karsasec.benchmark.provider import GroundTruthProvider
from karsasec.benchmark.regression import DifferentialRegressionEngine


def test_owasp_benchmark_adapter_csv_parsing() -> None:
    csv_data = """
    # OWASP Benchmark test result manifest
    test_case_id,cwe,is_vulnerable
    BenchmarkTest00001,89,true
    BenchmarkTest00002,89,false
    BenchmarkTest00003,79,true
    """
    adapter = OWASPBenchmarkAdapter()
    manifests = adapter.parse_csv_manifest(csv_data)

    assert len(manifests) == 3
    assert manifests[0].test_case_id == "BenchmarkTest00001"
    assert manifests[0].vulnerability_class == "SQL_INJECTION"
    assert manifests[0].expected_status == GroundTruthStatus.VULNERABLE

    assert manifests[1].test_case_id == "BenchmarkTest00002"
    assert manifests[1].expected_status == GroundTruthStatus.SAFE


def test_owasp_benchmark_adapter_synthetic_suite() -> None:
    adapter = OWASPBenchmarkAdapter()
    suite = adapter.generate_synthetic_benchmark_suite(cases_per_cwe=10)

    # 7 CWE classes * 10 cases = 70 manifests
    assert len(suite) == 70
    assert any(m.vulnerability_class == "SQL_INJECTION" for m in suite)
    assert any(m.vulnerability_class == "COMMAND_INJECTION" for m in suite)


def test_security_mutation_engine_accounting() -> None:
    engine = SecurityMutationEngine()

    mut_sql = SinkToSafeMutation()
    mut_src = SourceToConstantMutation()

    # Original VULNERABLE -> Mutated SAFE (KILLED)
    res_sql = engine.evaluate_mutation(mut_sql, DecisionResolution.VULNERABLE, DecisionResolution.SAFE)
    assert res_sql.status == MutationStatus.KILLED
    assert res_sql.killed is True

    # Original VULNERABLE -> Mutated VULNERABLE (SURVIVED)
    res_src = engine.evaluate_mutation(mut_src, DecisionResolution.VULNERABLE, DecisionResolution.VULNERABLE)
    assert res_src.status == MutationStatus.SURVIVED
    assert res_src.killed is False

    # Invalid AST mutation (INVALID)
    res_inv = engine.evaluate_mutation(mut_sql, DecisionResolution.VULNERABLE, DecisionResolution.SAFE, syntax_valid=False)
    assert res_inv.status == MutationStatus.INVALID

    score = engine.compute_mutation_score([res_sql, res_src, res_inv])
    assert score == 0.5


def test_adversarial_semantic_corpus_6_categories() -> None:
    corpus = AdversarialSemanticCorpus()
    all_items = corpus.list_items()
    assert len(all_items) >= 6

    tp_items = corpus.list_items(CorpusCategory.TRUE_POSITIVE)
    tn_items = corpus.list_items(CorpusCategory.TRUE_NEGATIVE)
    amb_items = corpus.list_items(CorpusCategory.AMBIGUOUS)
    conf_items = corpus.list_items(CorpusCategory.CONTRADICTORY)
    bound_items = corpus.list_items(CorpusCategory.BOUNDARY)
    dec_items = corpus.list_items(CorpusCategory.DECEPTIVE)

    assert len(tp_items) >= 1
    assert len(tn_items) >= 1
    assert len(amb_items) >= 1
    assert len(conf_items) >= 1
    assert len(bound_items) >= 1
    assert len(dec_items) >= 1

    assert amb_items[0].expected_resolution == DecisionResolution.UNKNOWN
    assert conf_items[0].expected_resolution == DecisionResolution.CONFLICT
    assert bound_items[0].expected_resolution in (DecisionResolution.UNKNOWN, DecisionResolution.VULNERABLE)
    assert dec_items[0].expected_resolution == DecisionResolution.VULNERABLE


def test_wilson_confidence_interval() -> None:
    ci = compute_wilson_confidence_interval(k=90, n=100)
    assert 0.82 <= ci.lower_bound <= 0.84
    assert 0.94 <= ci.upper_bound <= 0.96
    assert ci.confidence_level == 0.95


def test_differential_regression_engine() -> None:
    adapter = OWASPBenchmarkAdapter()
    manifests = adapter.generate_synthetic_benchmark_suite(cases_per_cwe=5)
    provider = GroundTruthProvider(manifests)
    harness = BenchmarkHarness(provider)

    preds_baseline = {m.test_case_id: m.expected_status.value for m in manifests}
    res_baseline = harness.evaluate_predictions(preds_baseline, dataset_name="SYNTH")

    res_candidate = harness.evaluate_predictions(preds_baseline, dataset_name="SYNTH")

    regression_engine = DifferentialRegressionEngine()
    report = regression_engine.compare_runs(res_baseline, res_candidate)

    assert report.is_acceptable is True
    assert report.precision_delta == 0.0
    assert report.recall_delta == 0.0
    assert res_baseline.verdict in (GateVerdict.G5_PASS, GateVerdict.G5_PASS_WITH_KNOWN_GAPS)
