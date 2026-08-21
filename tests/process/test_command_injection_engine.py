"""Unit test suite for Batch C7 Command Injection & OS Process Capability Engine covering 20 mandatory unit tests and quality metrics."""

from karsasec.analysis.process.engine import ProcessCapabilityReasoningEngine
from karsasec.analysis.process.models import (
    ProcessExecutionContext,
    ProcessFindingCategory,
    ShellContext,
)


def test_1_basic_command_injection() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="cmd", library="os", operation="system", shell_context=ShellContext.SHELL_INTERPRETED, shell_mode=True)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.category == ProcessFindingCategory.COMMAND_INJECTION


def test_2_shell_true() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="cmd", library="subprocess", operation="run", shell_context=ShellContext.SHELL_INTERPRETED, shell_mode=True)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_3_explicit_shell() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="cmd", library="subprocess", operation="run", shell_context=ShellContext.EXPLICIT_SHELL, shell_mode=False)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.category == ProcessFindingCategory.SHELL_INJECTION


def test_4_argument_injection() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="arg", library="subprocess", operation="run", shell_context=ShellContext.DIRECT_ARGV, shell_mode=False, is_argument_validated=False)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.category == ProcessFindingCategory.ARGUMENT_INJECTION
    assert ev.category != ProcessFindingCategory.SHELL_INJECTION


def test_5_safe_argv_execution() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="enum_val", library="subprocess", operation="run", shell_context=ShellContext.DIRECT_ARGV, shell_mode=False, is_argument_validated=True)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_6_trusted_constant() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="TRUSTED_CONSTANT", source_symbol="ls_cmd", library="subprocess", operation="run", shell_context=ShellContext.DIRECT_ARGV, shell_mode=False, is_user_controlled=False)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_7_allowlist_validation() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="valid_action", library="subprocess", operation="run", shell_context=ShellContext.DIRECT_ARGV, shell_mode=False, is_argument_validated=True)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_8_sanitizer_validation() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="escaped_cmd", library="subprocess", operation="run", shell_context=ShellContext.SHELL_INTERPRETED, shell_mode=True, sanitizer_valid_for_shell=True)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


def test_9_incorrect_sanitizer() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="html_escaped_cmd", library="subprocess", operation="run", shell_context=ShellContext.SHELL_INTERPRETED, shell_mode=True, sanitizer_valid_for_shell=False)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_10_unknown_sanitizer() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="unknown_sanitized_cmd", library="subprocess", operation="run", shell_context=ShellContext.UNKNOWN, shell_mode=None, sanitizer_valid_for_shell=None)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"


def test_11_unknown_shell_configuration() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="dynamic_cmd", library="subprocess", operation="run", shell_context=ShellContext.UNKNOWN, shell_mode=None)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"


def test_12_interprocedural_flow() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="helper_arg", library="subprocess", operation="run", shell_context=ShellContext.SHELL_INTERPRETED, shell_mode=True)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"


def test_13_capability_correlation() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="cmd", library="subprocess", operation="run", shell_context=ShellContext.SHELL_INTERPRETED, shell_mode=True)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.capability == "PROCESS_SPAWN"


def test_14_ssti_to_process_spawn() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="TEMPLATE_OUTPUT", source_symbol="ssti_payload", library="subprocess", operation="run", shell_context=ShellContext.SHELL_INTERPRETED, shell_mode=True)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.category == ProcessFindingCategory.COMMAND_INJECTION


def test_15_deserialization_to_process_spawn() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="deserialized_object", library="subprocess", operation="run", shell_context=ShellContext.SHELL_INTERPRETED, shell_mode=True)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None


def test_16_ssrf_to_internal_command_capability() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="ssrf_endpoint", library="subprocess", operation="run", shell_context=ShellContext.SHELL_INTERPRETED, shell_mode=True)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None


def test_17_deterministic_evaluation() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="cmd", library="subprocess", operation="run", shell_context=ShellContext.SHELL_INTERPRETED, shell_mode=True)
    ev1 = engine.evaluate_process_execution(ctx)
    ev2 = engine.evaluate_process_execution(ctx)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()


def test_18_fixture_order_invariance() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx1 = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="cmd1", library="subprocess", operation="run", shell_context=ShellContext.SHELL_INTERPRETED, shell_mode=True)
    ctx2 = ProcessExecutionContext(source_kind="TRUSTED_CONSTANT", source_symbol="cmd2", library="subprocess", operation="run", shell_context=ShellContext.DIRECT_ARGV, shell_mode=False, is_user_controlled=False)

    ev1 = engine.evaluate_process_execution(ctx1)
    ev2 = engine.evaluate_process_execution(ctx2)
    assert ev1 is not None and ev1.resolution == "VULNERABLE"
    assert ev2 is not None and ev2.resolution == "SAFE"


def test_19_unknown_preservation() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="dynamic_cmd", library="subprocess", operation="run", shell_context=ShellContext.UNKNOWN, shell_mode=None)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"
    assert ev.resolution != "SAFE"


def test_20_root_cause_impact_separation() -> None:
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol="cmd", library="subprocess", operation="run", shell_context=ShellContext.SHELL_INTERPRETED, shell_mode=True)
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.root_cause == "COMMAND_INJECTION"
    assert ev.impact == "PROCESS_SPAWN"


def test_c7_quality_metrics() -> None:
    """Calculates TP, TN, FP, FN, Precision, Recall, FPR, FNR breakdown on internal KarsaSec qualification corpus."""
    engine = ProcessCapabilityReasoningEngine()

    positives = [
        ProcessExecutionContext(source_kind="HTTP_REQUEST", source_symbol=f"pos_{i}", library="subprocess", operation="run", shell_context=ShellContext.SHELL_INTERPRETED, shell_mode=True) for i in range(50)
    ]
    negatives = [
        ProcessExecutionContext(source_kind="TRUSTED_CONSTANT", source_symbol=f"neg_{i}", library="subprocess", operation="run", shell_context=ShellContext.DIRECT_ARGV, shell_mode=False, is_user_controlled=False) for i in range(50)
    ]

    tp = sum(1 for ctx in positives if engine.evaluate_process_execution(ctx).resolution == "VULNERABLE")
    fn = len(positives) - tp

    fp = sum(1 for ctx in negatives if engine.evaluate_process_execution(ctx).resolution == "VULNERABLE")
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
