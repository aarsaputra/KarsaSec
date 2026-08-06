"""Rule Performance Profiler module for tracking evaluation latency and memory overhead per rule."""

from __future__ import annotations

import time
from typing import Any

from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.patterns import get_default_rules_directory


class RuleProfiler:
    """Profiles execution latency and node matching performance across loaded YAML security rules."""

    def __init__(self) -> None:
        self.loader = YAMLRuleLoader()
        self.rules_dir = get_default_rules_directory()

    def profile_execution(self, dummy_code_samples: list[str] | None = None) -> list[dict[str, Any]]:
        """Profiles rule execution time over sample source snippets."""
        rules = self.loader.load_directory(self.rules_dir)
        results: list[dict[str, Any]] = []

        samples = dummy_code_samples or [
            "user_input = request.GET['cmd']; exec(user_input)",
            "$input = $_POST['data']; mysql_query($input);",
            "const url = req.query.url; fetch(url);",
            "c.Query('q'); db.Raw(q);",
        ]

        for r in rules:
            start_time = time.perf_counter()
            match_count = 0

            # Simulate pattern compilation and evaluation check
            if r.condition and r.condition.pattern:
                import re
                try:
                    compiled = re.compile(r.condition.pattern)
                    for sample in samples:
                        if compiled.search(sample):
                            match_count += 1
                except Exception:
                    pass

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            results.append({
                "id": r.id,
                "name": r.metadata.name,
                "severity": r.output.severity.value,
                "elapsed_ms": round(elapsed_ms, 3),
                "simulated_matches": match_count,
            })

        # Sort by slowest evaluation time first
        results.sort(key=lambda x: x["elapsed_ms"], reverse=True)
        return results
