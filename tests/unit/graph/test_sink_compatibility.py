"""Unit tests for CompatibilityRegistry (E12-3)."""

from karsasec.graph.dataflow.compatibility import CompatibilityRegistry


def test_sanitizer_compatibility_matrix() -> None:
    # htmlspecialchars is NOT compatible with COMMAND_EXECUTION
    assert not CompatibilityRegistry.is_sanitizer_compatible(
        CompatibilityRegistry.HTML_ESCAPE, CompatibilityRegistry.COMMAND_EXECUTION
    )
    # htmlspecialchars IS compatible with HTML_OUTPUT
    assert CompatibilityRegistry.is_sanitizer_compatible(
        CompatibilityRegistry.HTML_ESCAPE, CompatibilityRegistry.HTML_OUTPUT
    )
    # escapeshellarg IS compatible with COMMAND_EXECUTION
    assert CompatibilityRegistry.is_sanitizer_compatible(
        CompatibilityRegistry.SHELL_ESCAPE, CompatibilityRegistry.COMMAND_EXECUTION
    )


def test_source_compatibility_matrix() -> None:
    assert CompatibilityRegistry.is_source_compatible("USER_INPUT", CompatibilityRegistry.COMMAND_EXECUTION)
    assert not CompatibilityRegistry.is_source_compatible("STATIC_LITERAL", CompatibilityRegistry.COMMAND_EXECUTION)
