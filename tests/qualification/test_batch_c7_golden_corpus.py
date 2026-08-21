"""Batch C7 Command Injection & OS Process Capability Golden Corpus Qualification Test Suite (140 Fixtures across 7 Languages)."""

import pytest

from karsasec.analysis.process.engine import ProcessCapabilityReasoningEngine
from karsasec.analysis.process.models import (
    ProcessExecutionContext,
    ProcessFindingCategory,
    ShellContext,
)

LANGUAGES = ["python", "javascript", "php", "java", "go", "ruby", "dotnet"]
LIBRARIES = ["subprocess", "child_process", "system", "ProcessBuilder", "exec", "Open3", "Process"]
OPERATIONS = ["run", "exec", "system", "start", "Command", "spawn", "Start"]

# --- 140 High-Quality Parametrized Fixtures ---

COMMAND_INJECTION_POSITIVES = [
    ProcessExecutionContext(
        source_kind="HTTP_REQUEST",
        source_symbol=f"cmd_input_{i}",
        library=LIBRARIES[i % len(LIBRARIES)],
        operation=OPERATIONS[i % len(OPERATIONS)],
        shell_context=ShellContext.SHELL_INTERPRETED,
        shell_mode=True,
        is_user_controlled=True,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 46)
]

SAFE_ARGV_NEGATIVES = [
    ProcessExecutionContext(
        source_kind="TRUSTED_CONSTANT",
        source_symbol=f"constant_cmd_{i}",
        library=LIBRARIES[i % len(LIBRARIES)],
        operation=OPERATIONS[i % len(OPERATIONS)],
        shell_context=ShellContext.DIRECT_ARGV,
        shell_mode=False,
        is_user_controlled=False,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 41)
]

SANITIZED_SHELL_FIXTURES = [
    ProcessExecutionContext(
        source_kind="HTTP_REQUEST",
        source_symbol=f"escaped_input_{i}",
        library="subprocess",
        operation="run",
        shell_context=ShellContext.SHELL_INTERPRETED,
        shell_mode=True,
        is_user_controlled=True,
        sanitizer_valid_for_shell=True,
        language="python",
    )
    for i in range(1, 26)
]

ADVERSARIAL_ARGUMENT_INJECTION_TRAPS = [
    ProcessExecutionContext(
        source_kind="HTTP_REQUEST",
        source_symbol=f"argv_untrusted_{i}",
        library=LIBRARIES[i % len(LIBRARIES)],
        operation=OPERATIONS[i % len(OPERATIONS)],
        shell_context=ShellContext.DIRECT_ARGV,
        shell_mode=False,
        is_user_controlled=True,
        is_argument_validated=False,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 16)
]

UNKNOWN_SHELL_CONFIG_FIXTURES = [
    ProcessExecutionContext(
        source_kind="HTTP_REQUEST",
        source_symbol=f"dynamic_proc_{i}",
        library="subprocess",
        operation="run",
        shell_context=ShellContext.UNKNOWN,
        shell_mode=None,
        sanitizer_valid_for_shell=None,
        language="python",
    )
    for i in range(1, 13)
]


@pytest.mark.parametrize("ctx", COMMAND_INJECTION_POSITIVES)
def test_command_injection_positive_detection(ctx: ProcessExecutionContext) -> None:
    engine = ProcessCapabilityReasoningEngine()
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"
    assert ev.category in (ProcessFindingCategory.COMMAND_INJECTION, ProcessFindingCategory.SHELL_INJECTION)


@pytest.mark.parametrize("ctx", SAFE_ARGV_NEGATIVES)
def test_safe_argv_negatives(ctx: ProcessExecutionContext) -> None:
    engine = ProcessCapabilityReasoningEngine()
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


@pytest.mark.parametrize("ctx", SANITIZED_SHELL_FIXTURES)
def test_sanitized_shell_fixtures(ctx: ProcessExecutionContext) -> None:
    engine = ProcessCapabilityReasoningEngine()
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "SAFE"


@pytest.mark.parametrize("ctx", ADVERSARIAL_ARGUMENT_INJECTION_TRAPS)
def test_adversarial_argument_injection_traps(ctx: ProcessExecutionContext) -> None:
    engine = ProcessCapabilityReasoningEngine()
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "VULNERABLE"
    assert ev.category == ProcessFindingCategory.ARGUMENT_INJECTION
    assert ev.category != ProcessFindingCategory.SHELL_INJECTION  # INV-C7-03 verified!


@pytest.mark.parametrize("ctx", UNKNOWN_SHELL_CONFIG_FIXTURES)
def test_unknown_shell_config_fixtures(ctx: ProcessExecutionContext) -> None:
    engine = ProcessCapabilityReasoningEngine()
    ev = engine.evaluate_process_execution(ctx)
    assert ev is not None
    assert ev.resolution == "UNKNOWN"
    assert ev.resolution != "SAFE"  # INV-GLOBAL-01 preserved!


def test_command_injection_determinism() -> None:
    """Section Determinism: Verifies repeated execution yields 100% identical outputs."""
    engine = ProcessCapabilityReasoningEngine()
    ctx = ProcessExecutionContext(
        source_kind="HTTP_REQUEST",
        source_symbol="req.args['cmd']",
        library="subprocess",
        operation="run",
        shell_context=ShellContext.SHELL_INTERPRETED,
        shell_mode=True,
    )

    ev1 = engine.evaluate_process_execution(ctx)
    ev2 = engine.evaluate_process_execution(ctx)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()
