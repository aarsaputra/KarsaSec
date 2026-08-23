"""OWASP Benchmark v1.2 Adapter for KarsaSec External Security Validation (Gate 5).

Maps OWASP Benchmark test cases and ground truth csv/manifest records to
independent GroundTruthManifest objects for OWASP Benchmark vulnerability classes:
- SQL Injection (CWE-89)
- Command Injection (CWE-78)
- Cross-Site Scripting (CWE-79)
- Path Traversal (CWE-22)
- Weak Cryptography (CWE-327)
- Weak Randomness (CWE-330)
- Insecure Cookie (CWE-614)
"""

from __future__ import annotations

from karsasec.benchmark.models import GroundTruthManifest, GroundTruthStatus


class OWASPBenchmarkAdapter:
    """Adapter parsing OWASP Benchmark test cases into GroundTruthManifests."""

    CWE_MAP = {
        "89": "SQL_INJECTION",
        "78": "COMMAND_INJECTION",
        "79": "CROSS_SITE_SCRIPTING",
        "22": "PATH_TRAVERSAL",
        "327": "WEAK_CRYPTOGRAPHY",
        "330": "WEAK_RANDOMNESS",
        "614": "INSECURE_COOKIE",
    }

    def __init__(self, dataset_version: str = "v1.2") -> None:
        self.dataset_version = dataset_version

    def parse_csv_manifest(self, csv_content: str) -> list[GroundTruthManifest]:
        """Parses OWASP Benchmark expected results CSV content.

        Format: test_case_id,cwe,is_vulnerable
        Example: BenchmarkTest00001,89,true
        """
        manifests: list[GroundTruthManifest] = []
        lines = csv_content.strip().splitlines()

        for line in lines:
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 3 or parts[0].lower() in ("test_case_id", "test_case", "testcase", "id"):
                continue

            tc_id, cwe_raw, vuln_raw = parts[0], parts[1], parts[2].lower()
            cwe_clean = cwe_raw.replace("CWE-", "")
            vuln_class = self.CWE_MAP.get(cwe_clean, f"CWE_{cwe_clean}")

            is_vuln = vuln_raw in ("true", "1", "vulnerable", "yes")
            gt_status = GroundTruthStatus.VULNERABLE if is_vuln else GroundTruthStatus.SAFE

            manifests.append(
                GroundTruthManifest(
                    test_case_id=tc_id,
                    dataset_name="OWASP_BENCHMARK",
                    vulnerability_class=vuln_class,
                    cwe=f"CWE-{cwe_clean}",
                    expected_status=gt_status,
                    file_path=f"owasp/{tc_id}.java",
                    line_number=42,
                    metadata={"dataset_version": self.dataset_version},
                )
            )

        return manifests

    def generate_synthetic_benchmark_suite(self, cases_per_cwe: int = 10) -> list[GroundTruthManifest]:
        """Generates a reproducible 70-case synthetic OWASP Benchmark manifest suite for offline testing."""
        manifests: list[GroundTruthManifest] = []
        counter = 1

        for cwe_code, vuln_class in self.CWE_MAP.items():
            for i in range(cases_per_cwe):
                tc_id = f"BenchmarkTest{counter:05d}"
                # Alternate between vulnerable and safe
                is_vuln = (i % 2 == 0)
                gt_status = GroundTruthStatus.VULNERABLE if is_vuln else GroundTruthStatus.SAFE

                manifests.append(
                    GroundTruthManifest(
                        test_case_id=tc_id,
                        dataset_name="OWASP_BENCHMARK",
                        vulnerability_class=vuln_class,
                        cwe=f"CWE-{cwe_code}",
                        expected_status=gt_status,
                        file_path=f"org/owasp/benchmark/testcode/{tc_id}.java",
                        line_number=40 + i,
                        sink_function="executeQuery" if cwe_code == "89" else "exec",
                        metadata={"synthetic": True},
                    )
                )
                counter += 1

        return manifests
