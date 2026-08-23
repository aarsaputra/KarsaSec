"""Unit tests verifying Adapter Integrity (INV-G5.3-01 & INV-G5.3-08)."""

from karsasec.benchmark.adapters.dvwa import DvwaManifestAdapter
from karsasec.benchmark.adapters.owasp_benchmark import OWASPBenchmarkAdapter


def test_owasp_adapter_manifest_generation() -> None:
    adapter = OWASPBenchmarkAdapter()
    manifests = adapter.generate_synthetic_benchmark_suite(cases_per_cwe=10)
    assert len(manifests) == 70
    assert manifests[0].dataset_name == "OWASP_BENCHMARK"


def test_dvwa_adapter_manifest_loading() -> None:
    adapter = DvwaManifestAdapter()
    cases = adapter.load_canonical_cases()
    assert len(cases) > 0
    for c in cases:
        assert c["dataset"] == "DVWA"
        assert "expected_status" in c
        assert "code_snippet" in c
