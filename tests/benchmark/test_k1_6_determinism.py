"""K1.6 Execution Determinism and Order Invariance Test Suite.

Verifies INV-K1.6-09 (100-pass run determinism) and INV-K1.6-10 (100-pass randomized order determinism).
"""

import hashlib
import json
import random
from pathlib import Path

from karsasec.analysis.taint.k1_integrated import analyze_k1
from karsasec.benchmark.k1_differential import normalize_finding


def test_k1_6_run_and_order_determinism() -> None:
    pos_dir = Path("benchmarks/k1/adversarial_positive")
    fixtures = sorted(list(pos_dir.glob("*.py")))

    base_digests = {}
    for fix_path in fixtures:
        code = fix_path.read_text(encoding="utf-8")
        norm = [normalize_finding(f) for f in analyze_k1(code)]
        digest = hashlib.sha256(json.dumps(norm, sort_keys=True).encode("utf-8")).hexdigest()
        base_digests[fix_path.name] = digest

    # 1. Run Determinism (100 passes on single fixture)
    target_fixture = fixtures[0]
    target_code = target_fixture.read_text(encoding="utf-8")
    target_digest = base_digests[target_fixture.name]

    for run_idx in range(100):
        norm = [normalize_finding(f) for f in analyze_k1(target_code)]
        digest = hashlib.sha256(json.dumps(norm, sort_keys=True).encode("utf-8")).hexdigest()
        assert (
            digest == target_digest
        ), f"Run determinism failure on iteration {run_idx} for {target_fixture.name}"

    # 2. Randomized Execution Order Determinism (100 randomized order passes)
    for pass_idx in range(100):
        shuffled = list(fixtures)
        random.seed(pass_idx)
        random.shuffle(shuffled)

        for fix_path in shuffled:
            code = fix_path.read_text(encoding="utf-8")
            norm = [normalize_finding(f) for f in analyze_k1(code)]
            digest = hashlib.sha256(json.dumps(norm, sort_keys=True).encode("utf-8")).hexdigest()
            assert (
                digest == base_digests[fix_path.name]
            ), f"Order determinism failure on pass {pass_idx} for {fix_path.name}"
