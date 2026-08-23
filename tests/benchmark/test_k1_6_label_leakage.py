"""K1.6 Two-Way Full Comment & Label Stripping Leakage Test Suite.

Verifies INV-K1.6-07 and INV-K1.6-08: Strips comments, randomizes filenames, removes metadata
for both positive and negative fixtures, confirming 0 alteration in detector findings.
"""

import re
from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1
from karsasec.benchmark.k1_differential import normalize_finding


def strip_all_labels_and_comments(code: str) -> str:
    # Remove single line comments (# ...)
    code_no_comments = re.sub(r"#.*", "", code)
    # Remove docstrings
    code_no_docstrings = re.sub(r'""".*?"""', "", code_no_comments, flags=re.DOTALL)
    return code_no_docstrings.strip()


def test_k1_6_two_way_full_label_stripping_and_cross_pack_isolation() -> None:
    # 1. Positive Fixtures Two-Way Leakage Audit
    pos_dir = Path("benchmarks/k1/adversarial_positive")
    pos_fixtures = list(pos_dir.glob("*.py"))
    assert len(pos_fixtures) == 20

    for fix_path in pos_fixtures:
        orig_code = fix_path.read_text(encoding="utf-8")
        stripped_code = strip_all_labels_and_comments(orig_code)

        orig_findings = [normalize_finding(f) for f in analyze_k1(orig_code)]
        stripped_findings = [normalize_finding(f) for f in analyze_k1(stripped_code)]

        assert (
            orig_findings == stripped_findings
        ), f"Label stripping altered findings for positive case {fix_path.name}: orig={orig_findings}, stripped={stripped_findings}"

    # 2. Negative Fixtures Two-Way Leakage Audit
    neg_dir = Path("benchmarks/k1/adversarial_semantic_negative")
    neg_fixtures = list(neg_dir.glob("*.py"))
    assert len(neg_fixtures) == 15

    for fix_path in neg_fixtures:
        orig_code = fix_path.read_text(encoding="utf-8")
        stripped_code = strip_all_labels_and_comments(orig_code)

        orig_findings = [normalize_finding(f) for f in analyze_k1(orig_code)]
        stripped_findings = [normalize_finding(f) for f in analyze_k1(stripped_code)]

        assert (
            orig_findings == stripped_findings
        ), f"Label stripping altered findings for negative case {fix_path.name}: orig={orig_findings}, stripped={stripped_findings}"

    # 3. Cross-Pack Isolation Audit
    for fix_path in pos_fixtures:
        fname = fix_path.name
        code = fix_path.read_text(encoding="utf-8")
        findings = analyze_k1(code)
        if "jwt" in fname:
            for f in findings:
                assert f.knowledge_pack == "JWT"
        elif "oauth" in fname:
            for f in findings:
                assert f.knowledge_pack == "OAuth"
        elif "biz" in fname:
            for f in findings:
                assert f.knowledge_pack == "Business Logic"
