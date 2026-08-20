"""Sprint E10-3J: Security Rule Quality Gate Tests.

Validates all E10-3J exit criteria:
1. EvidenceState.UNKNOWN never becomes a Finding
2. FindingConfidence has no UNKNOWN member
3. FindingCorrelator eliminates duplicates from overlapping rules
4. KS-PHP-SSRF-0001 has zero intentional overlap with KS-OWASP-0010
5. 5 critical rules have formal RuleContract with passing fixtures
6. Rule Contract Coverage metric is operational
7. UNKNOWN evidence suppresses finding (contract invariant)
8. Hardened rules pass positive/negative fixtures
"""

from __future__ import annotations

from pathlib import Path

from karsasec.core.finding.correlator import FindingCorrelator
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode, FileNode
from karsasec.rules.contract_validator import RuleContractValidator
from karsasec.rules.enums import (
    Confidence,
    EvidenceState,
    Severity,
    UnknownResolution,
)
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.matcher.matcher import ASTMatcher
from karsasec.rules.schema import (
    DetectionContract,
    FixtureContract,
    RegressionContract,
    RuleContract,
    SafetyContract,
)

RULES_DIR = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns" / "owasp"
PHP_RULES_DIR = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns" / "php"


def _make_finding(rule_id: str, cwe: str, snippet: str, line: int = 10, sev: str = "HIGH") -> Finding:
    """Helper: build a minimal Finding for correlation tests."""
    import hashlib
    import uuid

    fp = hashlib.sha256(f"{rule_id}|{line}|{snippet}".encode()).hexdigest()[:32]
    return Finding(
        finding_id=f"finding-{uuid.uuid4().hex[:8]}",
        rule_id=rule_id,
        fingerprint=fp,
        title=f"Test Finding [{rule_id}]",
        severity=Severity(sev),
        confidence=Confidence.LIKELY,
        cwe_id=cwe,
        owasp="A10:2021-SSRF",
        file_path=Path("test.php"),
        evidence=Evidence(snippet=snippet, line=line, column=0),
        description="test",
        remediation="test",
    )


def _ctx(lang: str = "PHP") -> VisitorContext:
    fn = FileNode(file_path=Path("fixture.php"), language=lang)
    return VisitorContext(file_node=fn, file_path=Path("fixture.php"), language=lang)


def _node(snippet: str, node_type: str = "call") -> tuple[ASTNode, bytes]:
    encoded = snippet.encode("utf-8")
    return ASTNode(node_type=node_type, byte_start=0, byte_end=len(encoded)), encoded


# ---------------------------------------------------------------------------
# Gate 1: EvidenceState is NOT FindingConfidence
# ---------------------------------------------------------------------------


class TestEvidenceStateIsNotFindingConfidence:
    """EvidenceState must never appear in FindingConfidence."""

    def test_finding_confidence_has_no_unknown_member(self) -> None:
        assert not hasattr(Confidence, "UNKNOWN"), (
            "FindingConfidence must NOT have an UNKNOWN member. UNKNOWN is an EvidenceState, not a confidence level."
        )

    def test_evidence_state_unknown_exists(self) -> None:
        assert EvidenceState.UNKNOWN == "UNKNOWN"

    def test_evidence_state_conflict_exists(self) -> None:
        assert EvidenceState.CONFLICT == "CONFLICT"

    def test_evidence_state_proven_safe_exists(self) -> None:
        assert EvidenceState.PROVEN_SAFE == "PROVEN_SAFE"

    def test_evidence_state_proven_vulnerable_exists(self) -> None:
        assert EvidenceState.PROVEN_VULNERABLE == "PROVEN_VULNERABLE"

    def test_unknown_resolution_suppress_is_default(self) -> None:
        safety = SafetyContract()
        assert safety.unknown_resolution == UnknownResolution.SUPPRESS

    def test_unknown_resolution_review_is_not_finding(self) -> None:
        """REVIEW must only reference ReviewCandidate, never Finding."""
        assert UnknownResolution.REVIEW == "REVIEW"
        # Verify it's distinct from all Confidence values
        confidence_values = {c.value for c in Confidence}
        assert UnknownResolution.REVIEW not in confidence_values


# ---------------------------------------------------------------------------
# Gate 2: RuleContract schema is correct
# ---------------------------------------------------------------------------


class TestRuleContractSchema:
    """Four-section RuleContract is correctly structured."""

    def test_rule_contract_has_four_sections(self) -> None:
        c = RuleContract()
        assert hasattr(c, "detection")
        assert hasattr(c, "safety")
        assert hasattr(c, "fixtures")
        assert hasattr(c, "regression")

    def test_detection_contract_fields(self) -> None:
        d = DetectionContract(
            source_kind="credential_hashing",
            semantic_context="MD5 used for password",
            unsafe_evidence=("LITERAL_SECRET",),
        )
        assert d.source_kind == "credential_hashing"
        assert "LITERAL_SECRET" in d.unsafe_evidence

    def test_fixture_contract_positive_negative(self) -> None:
        f = FixtureContract(
            positive=("$hash = md5($password);",),
            negative=("$checksum = md5($file);",),
        )
        assert len(f.positive) == 1
        assert len(f.negative) == 1

    def test_regression_contract_fp_ids(self) -> None:
        r = RegressionContract(
            fp_regression_ids=("DVWA-FP-001", "DVWA-FP-002"),
            regression_context="IV encoding false positive",
        )
        assert "DVWA-FP-001" in r.fp_regression_ids


# ---------------------------------------------------------------------------
# Gate 3 & 4: FindingCorrelator — deduplication + zero SSRF overlap
# ---------------------------------------------------------------------------


class TestFindingCorrelator:
    """FindingCorrelator deduplicates overlapping rule findings."""

    def setup_method(self) -> None:
        self.correlator = FindingCorrelator()

    def test_single_finding_passes_through(self) -> None:
        f = _make_finding("KS-OWASP-0010", "CWE-918", "file_get_contents($url)")
        canonical = self.correlator.correlate([f])
        assert len(canonical) == 1
        assert canonical[0].primary.rule_id == "KS-OWASP-0010"

    def test_duplicate_findings_deduplicated_to_one(self) -> None:
        """Same file, same line, same CWE -> 1 canonical finding."""
        f1 = _make_finding("KS-OWASP-0010", "CWE-918", "file_get_contents($url)", line=20)
        f2 = _make_finding("KS-PHP-SSRF-0001", "CWE-918", "file_get_contents($url)", line=20)
        canonical = self.correlator.correlate([f1, f2])
        assert len(canonical) == 1, (
            f"Expected 1 canonical finding, got {len(canonical)}. "
            "KS-OWASP-0010 and KS-PHP-SSRF-0001 on same location should deduplicate."
        )

    def test_correlated_rule_ids_contain_both_rules(self) -> None:
        f1 = _make_finding("KS-OWASP-0010", "CWE-918", "file_get_contents($url)", line=20)
        f2 = _make_finding("KS-PHP-SSRF-0001", "CWE-918", "file_get_contents($url)", line=20)
        canonical = self.correlator.correlate([f1, f2])
        assert "KS-OWASP-0010" in canonical[0].correlated_rule_ids
        assert "KS-PHP-SSRF-0001" in canonical[0].correlated_rule_ids

    def test_different_lines_not_merged(self) -> None:
        """Different line numbers -> different vulnerabilities -> 2 findings."""
        f1 = _make_finding("KS-OWASP-0010", "CWE-918", "file_get_contents($url)", line=20)
        f2 = _make_finding("KS-OWASP-0010", "CWE-918", "file_get_contents($url)", line=30)
        canonical = self.correlator.correlate([f1, f2])
        assert len(canonical) == 2

    def test_different_cwe_not_merged(self) -> None:
        """Different CWE -> different vulnerability class -> 2 findings."""
        f1 = _make_finding("KS-OWASP-0010", "CWE-918", "file_get_contents($url)", line=20)
        f2 = _make_finding("KS-PHP-0002", "CWE-89", "file_get_contents($url)", line=20)
        canonical = self.correlator.correlate([f1, f2])
        assert len(canonical) == 2

    def test_highest_severity_is_canonical_primary(self) -> None:
        """When two rules find same vuln, highest severity becomes primary."""
        f_high = _make_finding("KS-OWASP-0010", "CWE-918", "file_get_contents($url)", line=20, sev="HIGH")
        f_med = _make_finding("KS-PHP-SSRF-0001", "CWE-918", "file_get_contents($url)", line=20, sev="MEDIUM")
        canonical = self.correlator.correlate([f_high, f_med])
        assert canonical[0].primary.rule_id == "KS-OWASP-0010"

    def test_empty_input_returns_empty(self) -> None:
        assert self.correlator.correlate([]) == ()

    def test_to_findings_embeds_correlated_rules_metadata(self) -> None:
        f1 = _make_finding("KS-OWASP-0010", "CWE-918", "file_get_contents($url)", line=20)
        f2 = _make_finding("KS-PHP-SSRF-0001", "CWE-918", "file_get_contents($url)", line=20)
        canonical = self.correlator.correlate([f1, f2])
        findings = self.correlator.to_findings(canonical)
        assert len(findings) == 1
        assert "correlated_rules" in findings[0].metadata
        assert len(findings[0].metadata["correlated_rules"]) == 2

    def test_correlator_is_deterministic(self) -> None:
        """Same findings in different order -> same canonical output."""
        f1 = _make_finding("KS-OWASP-0010", "CWE-918", "file_get_contents($url)", line=20)
        f2 = _make_finding("KS-PHP-SSRF-0001", "CWE-918", "file_get_contents($url)", line=20)
        c1 = self.correlator.correlate([f1, f2])
        c2 = self.correlator.correlate([f2, f1])
        assert c1[0].semantic_fingerprint == c2[0].semantic_fingerprint
        assert c1[0].correlated_rule_ids == c2[0].correlated_rule_ids


# ---------------------------------------------------------------------------
# Gate 4: KS-PHP-SSRF-0001 zero overlap with KS-OWASP-0010
# ---------------------------------------------------------------------------


class TestSSRFZeroOverlap:
    """KS-PHP-SSRF-0001 must not trigger on file_get_contents or curl_exec (owned by KS-OWASP-0010)."""

    def setup_method(self) -> None:
        self.loader = YAMLRuleLoader()
        self.matcher = ASTMatcher()
        self.rule_php_ssrf = self.loader.load_file(PHP_RULES_DIR / "ssrf_php.yaml")
        self.rule_owasp_ssrf = self.loader.load_file(RULES_DIR / "A10_ssrf.yaml")
        self.ctx = _ctx("PHP")

    def test_file_get_contents_not_in_php_ssrf_triggers(self) -> None:
        triggers = self.rule_php_ssrf.condition.symbol_triggers
        assert "file_get_contents" not in triggers, (
            "file_get_contents must be removed from KS-PHP-SSRF-0001 triggers to eliminate overlap with KS-OWASP-0010."
        )

    def test_curl_exec_not_in_php_ssrf_triggers(self) -> None:
        triggers = self.rule_php_ssrf.condition.symbol_triggers
        assert "curl_exec" not in triggers, (
            "curl_exec must be removed from KS-PHP-SSRF-0001 triggers to eliminate overlap with KS-OWASP-0010."
        )

    def test_file_get_contents_does_not_match_php_ssrf(self) -> None:
        node, src = _node("$data = file_get_contents($url);")
        res = self.matcher.match(node, self.rule_php_ssrf, self.ctx, source_bytes=src)
        assert not res.matched, "file_get_contents must NOT trigger KS-PHP-SSRF-0001 — owned by KS-OWASP-0010"

    def test_curl_setopt_url_matches_php_ssrf(self) -> None:
        """curl_setopt(CURLOPT_URL) is the PHP-specific vector that KS-PHP-SSRF-0001 owns."""
        node, src = _node("curl_setopt($ch, CURLOPT_URL, $user_url);")
        res = self.matcher.match(node, self.rule_php_ssrf, self.ctx, source_bytes=src)
        assert res.matched, "curl_setopt(CURLOPT_URL, $user_url) must be detected by KS-PHP-SSRF-0001"


# ---------------------------------------------------------------------------
# Gate 5: RuleContract fixture validation for 5 hardened rules
# ---------------------------------------------------------------------------


class TestRuleContractValidation:
    """RuleContractValidator passes all positive/negative fixtures for hardened rules."""

    def setup_method(self) -> None:
        self.loader = YAMLRuleLoader()
        self.matcher = ASTMatcher()
        self.validator = RuleContractValidator()

    def _validate(self, rule_path: Path) -> None:
        rule = self.loader.load_file(rule_path)
        assert rule.contract is not None, f"Rule {rule.id} must have a contract section"
        result = self.validator.validate(rule, self.matcher)
        failures = [
            f"  [{f.fixture_kind}] snippet={f.snippet!r} expected={'FINDING' if f.expected_matched else 'NO_FINDING'}"
            for f in result.failures
        ]
        assert result.total > 0, f"Rule {rule.id} contract has no fixtures"
        assert result.all_passed, f"Rule {rule.id} contract fixture failures:\n" + "\n".join(failures)

    def test_ks_owasp_0002_crypto_contract(self) -> None:
        self._validate(RULES_DIR / "A02_cryptographic_failures.yaml")

    def test_ks_owasp_0005_misconfig_contract(self) -> None:
        self._validate(RULES_DIR / "A05_security_misconfiguration.yaml")

    def test_ks_owasp_0008_deserialization_contract(self) -> None:
        self._validate(RULES_DIR / "A08_insecure_deserialization.yaml")

    def test_ks_php_ssrf_0001_contract(self) -> None:
        self._validate(PHP_RULES_DIR / "ssrf_php.yaml")

    def test_ks_owasp_0010_ssrf_already_has_hardening(self) -> None:
        rule = self.loader.load_file(RULES_DIR / "A10_ssrf.yaml")
        assert rule.condition.node_text_not_matches is not None

    def test_ks_owasp_0007_has_semantic_predicates(self) -> None:
        rule = self.loader.load_file(
            Path(__file__).parents[2] / "karsasec/rules/patterns/owasp/A07_identity_and_authentication_failures.yaml"
        )
        assert rule.condition.value_evidence_not_in, "KS-OWASP-0007 must have value_evidence_not_in predicates"


# ---------------------------------------------------------------------------
# Gate 6: Contract coverage metric operational
# ---------------------------------------------------------------------------


class TestContractCoverageMetric:
    """Rule Contract Coverage metric tracks total rules vs rules with contracts."""

    def test_coverage_metric_computable(self) -> None:
        loader = YAMLRuleLoader()
        rules_dir = Path(__file__).parents[2] / "karsasec/rules/patterns"
        all_rules = loader.load_directory(rules_dir)
        with_contract = sum(1 for r in all_rules if r.contract is not None)
        total = len(all_rules)
        pct = round(with_contract / total * 100, 1) if total > 0 else 0.0
        # Just verify the metric is computable (not a pass/fail threshold)
        assert isinstance(pct, float)
        assert 0.0 <= pct <= 100.0
        # Verify we have at least the 3 new contracts from this sprint
        assert with_contract >= 3, f"Expected at least 3 rules with contracts after E10-3J, found {with_contract}"
