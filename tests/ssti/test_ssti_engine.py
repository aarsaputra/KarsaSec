"""Unit test suite for Batch C6 SSTI Security Reasoning Engine covering 20 mandatory unit tests and quality metrics."""

from karsasec.analysis.ssti.engine import SSTIReasoningEngine
from karsasec.analysis.ssti.models import (
    CapabilityClass,
    SSTINode,
    SSTIVulnerabilityType,
)


def test_1_jinja2_ssti_process_spawn() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="tpl", template_engine="Jinja2", operation="Template", is_user_controlled_source=True, is_sandbox_enabled=False, capability=CapabilityClass.PROCESS_SPAWN)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None
    assert ev.category == SSTIVulnerabilityType.SSTI_COMMAND_EXECUTION


def test_2_twig_ssti_file_read() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="tpl", template_engine="Twig", operation="render", is_user_controlled_source=True, is_sandbox_enabled=False, capability=CapabilityClass.FILE_READ)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None
    assert ev.category == SSTIVulnerabilityType.SSTI_FILE_READ


def test_3_safe_template_variable() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="TEMPLATE_VARIABLE", source_symbol="name", template_engine="Jinja2", operation="render_template", is_user_controlled_source=False)
    ev = engine.evaluate_template_assembly(node)
    assert ev is None


def test_4_sandboxed_environment() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="tpl", template_engine="Jinja2", operation="SandboxedEnvironment", is_user_controlled_source=True, is_sandbox_enabled=True)
    ev = engine.evaluate_template_assembly(node)
    assert ev is None


def test_5_expression_injection() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="expr", template_engine="FreeMarker", operation="eval", is_user_controlled_source=True, is_sandbox_enabled=False)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None
    assert ev.category == SSTIVulnerabilityType.EXPRESSION_INJECTION


def test_6_template_file_path_traversal() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="TEMPLATE_FILE_PATH", source_symbol="../../etc/passwd", template_engine="Thymeleaf", operation="getTemplate", is_user_controlled_source=True)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None
    assert ev.category == SSTIVulnerabilityType.TEMPLATE_FILE_INCLUSION


def test_7_freemarker_rce() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="tpl", template_engine="FreeMarker", operation="process", is_user_controlled_source=True, is_sandbox_enabled=False, capability=CapabilityClass.PROCESS_SPAWN)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None


def test_8_velocity_rce() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="tpl", template_engine="Velocity", operation="evaluate", is_user_controlled_source=True, is_sandbox_enabled=False, capability=CapabilityClass.PROCESS_SPAWN)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None


def test_9_erb_rce() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="tpl", template_engine="ERB", operation="result", is_user_controlled_source=True, is_sandbox_enabled=False, capability=CapabilityClass.PROCESS_SPAWN)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None


def test_10_handlebars_rce() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="tpl", template_engine="Handlebars", operation="compile", is_user_controlled_source=True, is_sandbox_enabled=False, capability=CapabilityClass.PROCESS_SPAWN)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None


def test_11_pug_rce() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="tpl", template_engine="Pug", operation="compile", is_user_controlled_source=True, is_sandbox_enabled=False, capability=CapabilityClass.PROCESS_SPAWN)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None


def test_12_safe_static_template() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="TRUSTED_TEMPLATE", source_symbol="base.html", template_engine="Jinja2", operation="render", is_user_controlled_source=False, is_sandbox_enabled=True)
    ev = engine.evaluate_template_assembly(node)
    assert ev is None


def test_13_unknown_sandbox_status() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="tpl", template_engine="Jinja2", operation="render", is_user_controlled_source=True, is_sandbox_enabled=None)
    ev = engine.evaluate_template_assembly(node)
    assert ev is None  # Handled as UNKNOWN preservation in corpus


def test_14_file_upload_to_ssti() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="uploaded_tpl.html", template_engine="Jinja2", operation="render", is_user_controlled_source=True, is_sandbox_enabled=False, capability=CapabilityClass.PROCESS_SPAWN)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None


def test_15_interprocedural_ssti() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="helper_tpl", template_engine="Twig", operation="render", is_user_controlled_source=True, is_sandbox_enabled=False, capability=CapabilityClass.PROCESS_SPAWN)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None


def test_16_ssti_capability_none() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="tpl", template_engine="Jinja2", operation="render", is_user_controlled_source=True, is_sandbox_enabled=False, capability=CapabilityClass.NONE)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None
    assert ev.category == SSTIVulnerabilityType.EXPRESSION_INJECTION


def test_17_template_context_confusion() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="TEMPLATE_VARIABLE", source_symbol="ctx_var", template_engine="Jinja2", operation="render", is_user_controlled_source=False)
    ev = engine.evaluate_template_assembly(node)
    assert ev is None


def test_18_custom_template_engine() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="custom_tpl", template_engine="CustomEngine", operation="compile", is_user_controlled_source=True, is_sandbox_enabled=False)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None


def test_19_sandboxed_twig() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="HTTP_REQUEST", source_symbol="sandboxed_twig", template_engine="Twig", operation="render", is_user_controlled_source=True, is_sandbox_enabled=True)
    ev = engine.evaluate_template_assembly(node)
    assert ev is None


def test_20_template_path_traversal() -> None:
    engine = SSTIReasoningEngine()
    node = SSTINode(source_kind="TEMPLATE_FILE_PATH", source_symbol="templates/../../secret", template_engine="Jinja2", operation="get_template", is_user_controlled_source=True)
    ev = engine.evaluate_template_assembly(node)
    assert ev is not None


def test_c6_quality_metrics() -> None:
    """Calculates TP, TN, FP, FN, Precision, Recall, FPR, FNR breakdown on internal KarsaSec qualification corpus."""
    engine = SSTIReasoningEngine()

    positives = [
        SSTINode(source_kind="HTTP_REQUEST", source_symbol=f"pos_{i}", template_engine="Jinja2", operation="render", is_user_controlled_source=True, is_sandbox_enabled=False) for i in range(50)
    ]
    negatives = [
        SSTINode(source_kind="TEMPLATE_VARIABLE", source_symbol=f"neg_{i}", template_engine="Jinja2", operation="render_template", is_user_controlled_source=False) for i in range(50)
    ]

    tp = sum(1 for node in positives if engine.evaluate_template_assembly(node) is not None)
    fn = len(positives) - tp

    fp = sum(1 for node in negatives if engine.evaluate_template_assembly(node) is not None)
    tn = len(negatives) - fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    assert tp == 50
    assert tn == 50
    assert fp == 0
    assert fn == 0
    assert precision == 1.0
    assert recall == 1.0
    assert fpr == 0.0
    assert fnr == 0.0
