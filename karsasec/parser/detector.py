"""Deterministic Language and Framework Detector orchestrator module."""

from pathlib import Path
from karsasec.core.context import ProjectProfile
from karsasec.parser.framework import FrameworkDetector
from karsasec.parser.language import LanguageDetector
from karsasec.parser.profile import ProjectProfiler

class ProjectDetector:
    """Orchestrates multi-stage project profiling pipeline: Language -> Framework -> Profile."""

    def __init__(
        self,
        root_path: Path,
        language_detector: LanguageDetector = LanguageDetector(),
        framework_detector: FrameworkDetector = FrameworkDetector(),
    ) -> None:
        self.root_path = root_path
        self.profiler = ProjectProfiler(
            language_detector=language_detector,
            framework_detector=framework_detector
        )

    def detect(self) -> ProjectProfile:
        """Executes project profiling pipeline and returns structured ProjectProfile."""
        return self.profiler.profile(self.root_path)

def detect_project(target_path: Path) -> ProjectProfile:
    """Helper function to run detection pipeline on a given path."""
    detector = ProjectDetector(target_path)
    return detector.detect()
