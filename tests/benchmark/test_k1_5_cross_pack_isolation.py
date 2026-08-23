"""K1.5 Adversarial Cross-Pack Isolation Test Suite (Task K1.5)."""

from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1


def test_k1_5_adversarial_cross_pack_isolation() -> None:
    pos_dir = Path("benchmarks/k1/adversarial_positive")
    fixtures = sorted(list(pos_dir.glob("*.py")))

    for fix_path in fixtures:
        fname = fix_path.name
        code = fix_path.read_text(encoding="utf-8")
        findings = analyze_k1(code)

        if "jwt" in fname:
            for f in findings:
                assert f.knowledge_pack == "JWT", f"Adversarial cross-pack leakage in {fname}: {f.knowledge_pack}"
        elif "oauth" in fname:
            for f in findings:
                assert f.knowledge_pack == "OAuth", f"Adversarial cross-pack leakage in {fname}: {f.knowledge_pack}"
        elif "biz" in fname:
            for f in findings:
                assert f.knowledge_pack == "Business Logic", f"Adversarial cross-pack leakage in {fname}: {f.knowledge_pack}"
