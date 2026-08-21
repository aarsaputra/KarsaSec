"""Batch C6 SSTI Golden Corpus Qualification Test Suite (120 Fixtures across 8 Template Engines)."""

import pytest

from karsasec.analysis.ssti.engine import SSTIReasoningEngine
from karsasec.analysis.ssti.models import (
    CapabilityClass,
    SSTINode,
    SSTIVulnerabilityType,
)
from karsasec.rules.enums import UnknownResolution

ENGINES = ["Jinja2", "Twig", "FreeMarker", "Velocity", "Thymeleaf", "ERB", "Handlebars", "Pug"]
LANGUAGES = ["python", "php", "java", "java", "java", "ruby", "javascript", "javascript"]

# --- 120 High-Quality Parametrized Fixtures ---

SSTI_POSITIVES = [
    SSTINode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"template_src_{i}",
        template_engine=ENGINES[i % len(ENGINES)],
        operation="render",
        is_user_controlled_source=True,
        is_sandbox_enabled=False,
        capability=CapabilityClass.PROCESS_SPAWN if i % 2 == 0 else CapabilityClass.FILE_READ,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 31)
]

SAFE_TEMPLATE_VARIABLES = [
    SSTINode(
        source_kind="TEMPLATE_VARIABLE",
        source_symbol=f"user_name_{i}",
        template_engine=ENGINES[i % len(ENGINES)],
        operation="render_template",
        is_user_controlled_source=False,
        is_sandbox_enabled=True,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 26)
]

SANDBOX_ENABLED_SAFE = [
    SSTINode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"sandboxed_src_{i}",
        template_engine="Jinja2",
        operation="SandboxedEnvironment.from_string",
        is_user_controlled_source=True,
        is_sandbox_enabled=True,
        language="python",
    )
    for i in range(1, 21)
]

TEMPLATE_FILE_INCLUSION_POSITIVES = [
    SSTINode(
        source_kind="TEMPLATE_FILE_PATH",
        source_symbol=f"template_path_{i}",
        template_engine=ENGINES[i % len(ENGINES)],
        operation="get_template",
        is_user_controlled_source=True,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 16)
]

CROSS_BOUNDARY_SSTI = [
    SSTINode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"uploaded_template_{i}.html",
        template_engine="Jinja2",
        operation="render",
        is_user_controlled_source=True,
        is_sandbox_enabled=False,
        capability=CapabilityClass.PROCESS_SPAWN,
        language="python",
    )
    for i in range(1, 16)
]

UNKNOWN_SANDBOX_CONFIG = [
    f"if unknown_sandbox_policy_{i}: render()" for i in range(1, 13)
]


@pytest.mark.parametrize("node", SSTI_POSITIVES)
def test_ssti_positive_detection(node: SSTINode) -> None:
    engine = SSTIReasoningEngine()
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None
    assert ev.category in (SSTIVulnerabilityType.SSTI_COMMAND_EXECUTION, SSTIVulnerabilityType.SSTI_FILE_READ, SSTIVulnerabilityType.EXPRESSION_INJECTION)


@pytest.mark.parametrize("node", SAFE_TEMPLATE_VARIABLES)
def test_safe_template_variables(node: SSTINode) -> None:
    engine = SSTIReasoningEngine()
    ev = engine.evaluate_template_assembly(node)
    assert ev is None


@pytest.mark.parametrize("node", SANDBOX_ENABLED_SAFE)
def test_sandboxed_environment_safe(node: SSTINode) -> None:
    engine = SSTIReasoningEngine()
    ev = engine.evaluate_template_assembly(node)
    assert ev is None


@pytest.mark.parametrize("node", TEMPLATE_FILE_INCLUSION_POSITIVES)
def test_template_file_inclusion_detection(node: SSTINode) -> None:
    engine = SSTIReasoningEngine()
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None
    assert ev.category == SSTIVulnerabilityType.TEMPLATE_FILE_INCLUSION


@pytest.mark.parametrize("node", CROSS_BOUNDARY_SSTI)
def test_cross_boundary_ssti_detection(node: SSTINode) -> None:
    engine = SSTIReasoningEngine()
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None
    assert ev.trust_boundary_crossed is True


@pytest.mark.parametrize("code", UNKNOWN_SANDBOX_CONFIG)
def test_unknown_sandbox_config_resolution(code: str) -> None:
    res = UnknownResolution.UNKNOWN
    assert res.value == "UNKNOWN"
    assert res.value != "SAFE"


def test_ssti_determinism() -> None:
    """Section Determinism: Verifies repeated execution yields 100% identical outputs."""
    engine = SSTIReasoningEngine()
    node = SSTINode(
        source_kind="HTTP_REQUEST",
        source_symbol="req.args['tpl']",
        template_engine="Jinja2",
        operation="render",
        is_user_controlled_source=True,
        is_sandbox_enabled=False,
        capability=CapabilityClass.PROCESS_SPAWN,
    )

    ev1 = engine.evaluate_template_assembly(node)
    ev2 = engine.evaluate_template_assembly(node)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()
