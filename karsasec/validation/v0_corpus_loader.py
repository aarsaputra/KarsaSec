"""Corpus Loader for Phase V0 Real-World Benchmark Samples."""

from __future__ import annotations

import json
from pathlib import Path
from collections.abc import Sequence

from karsasec.validation.v0_models import BenchmarkSample, GroundTruthFinding


class CorpusLoader:
    """Loads Phase V0 real-world security benchmark samples from filesystem or memory."""

    @staticmethod
    def load_from_dir(corpus_dir: str | Path) -> Sequence[BenchmarkSample]:
        """Loads all BenchmarkSample instances from a directory structure."""
        base_path = Path(corpus_dir)
        if not base_path.exists() or not base_path.is_dir():
            return ()

        samples: list[BenchmarkSample] = []
        for cat_dir in sorted(base_path.iterdir()):
            if not cat_dir.is_dir():
                continue

            meta_file = cat_dir / "metadata.json"
            vuln_file = cat_dir / "vulnerable.py"
            fix_file = cat_dir / "fixed.py"
            mut_file = cat_dir / "mutated.py"

            if not (meta_file.exists() and vuln_file.exists()):
                continue

            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            vuln_code = vuln_file.read_text(encoding="utf-8")
            fix_code = fix_file.read_text(encoding="utf-8") if fix_file.exists() else ""
            mut_code = mut_file.read_text(encoding="utf-8") if mut_file.exists() else vuln_code

            gt = GroundTruthFinding.create(
                vuln_class=meta.get("vuln_class", cat_dir.name.upper()),
                expected_severity=meta.get("expected_severity", "HIGH"),
                expected_decision=meta.get("expected_decision", "BLOCK"),
                expected_admission=meta.get("expected_admission", "BLOCKED"),
            )

            sample = BenchmarkSample.create(
                category=meta.get("category", cat_dir.name),
                name=meta.get("name", cat_dir.name),
                vulnerable_code=vuln_code,
                fixed_code=fix_code,
                mutated_code=mut_code,
                ground_truth=gt,
            )
            samples.append(sample)

        return tuple(samples)
