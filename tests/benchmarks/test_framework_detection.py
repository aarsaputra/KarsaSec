"""Performance benchmark for FrameworkDetector."""

import time
from pathlib import Path

from karsasec.framework.detector import FrameworkDetector


def test_framework_detection_benchmark():
    detector = FrameworkDetector()
    target_path = Path("security_corpus/python/flask_django/vulnerable")

    start = time.perf_counter()
    for _ in range(100):
        detector.detect(target_path)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    print(f"\n[BENCHMARK] 100 Framework Detector Iterations Elapsed Time: {elapsed_ms:.2f} ms")
    assert elapsed_ms < 1000.0, f"Framework detection benchmark exceeded threshold: {elapsed_ms:.2f} ms"
