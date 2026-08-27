from karsasec.framework.extractors.base import ExtractorContext, ExtractionResult, SemanticExtractor

from karsasec.framework.extractors.registry import ExtractorRegistry


class MockSuccessExtractor(SemanticExtractor):
    def __init__(self, name: str, priority: int) -> None:
        self._name = name
        self._priority = priority

    @property
    def name(self) -> str:
        return self._name

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("FLASK",)

    def extract(self, ctx: ExtractorContext) -> ExtractionResult:
        res = ExtractionResult()
        res.warnings.append(f"{self.name}_success")
        return res


class MockFailingExtractor(SemanticExtractor):
    @property
    def name(self) -> str:
        return "FailingExtractor"

    @property
    def priority(self) -> int:
        return 50

    @property
    def supported_frameworks(self) -> tuple[str, ...]:
        return ("FLASK",)

    def extract(self, ctx: ExtractorContext) -> ExtractionResult:
        raise ValueError("Simulated extractor crash")


def test_registry_deterministic_sorting() -> None:
    """Extractors with same priority must be sorted deterministically by name."""
    registry = ExtractorRegistry()
    ext_z = MockSuccessExtractor("ZetaExtractor", 100)
    ext_a = MockSuccessExtractor("AlphaExtractor", 100)
    ext_b = MockSuccessExtractor("BetaExtractor", 50)

    registry.register(ext_z)
    registry.register(ext_a)
    registry.register(ext_b)

    resolved = registry.resolve_by_framework("FLASK")
    names = [e.name for e in resolved]
    assert names == ["BetaExtractor", "AlphaExtractor", "ZetaExtractor"]


def test_registry_error_isolation() -> None:
    """One broken extractor must NOT halt or corrupt remaining extractors (INV-E10-SEM-08)."""
    registry = ExtractorRegistry()
    ext_1 = MockSuccessExtractor("Extractor1", 10)
    ext_fail = MockFailingExtractor()
    ext_2 = MockSuccessExtractor("Extractor2", 90)

    registry.register(ext_1)
    registry.register(ext_fail)
    registry.register(ext_2)

    ctx = ExtractorContext(framework="FLASK")
    result, diagnostics = registry.extract_all(ctx)

    # Success extractors completed
    assert "Extractor1_success" in result.warnings
    assert "Extractor2_success" in result.warnings

    # Error recorded in diagnostics without breaking execution
    assert len(diagnostics) == 1
    assert diagnostics[0]["extractor_name"] == "FailingExtractor"
    assert "Simulated extractor crash" in diagnostics[0]["error_message"]
