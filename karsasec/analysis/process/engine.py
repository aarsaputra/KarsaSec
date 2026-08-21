"""Command Injection & OS Process Capability Reasoning Engine for Batch C7."""

from __future__ import annotations

from karsasec.analysis.process.models import (
    ProcessEvidence,
    ProcessExecutionContext,
    ProcessFindingCategory,
    ShellContext,
)


class ProcessCapabilityReasoningEngine:
    """Deterministic reasoning engine for OS Command Injection, Shell Injection, and Process Capabilities."""

    def evaluate_process_execution(self, ctx: ProcessExecutionContext) -> ProcessEvidence | None:
        """Evaluates process execution context, shell mode, sanitization, argument validation, and capability."""
        # INV-C7-08: Trusted constant command is not attacker-controlled command
        if not ctx.is_user_controlled or ctx.source_kind == "TRUSTED_CONSTANT":
            return ProcessEvidence(
                category=ProcessFindingCategory.PROCESS_EXECUTION,
                root_cause="TRUSTED_CONSTANT",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                library=ctx.library,
                operation=ctx.operation,
                shell_context=ctx.shell_context.value,
                shell_mode=ctx.shell_mode,
                argument_validation=True,
                sanitization_valid=True,
                capability=ctx.capability.value,
                impact="NONE",
                trust_boundary_crossed=False,
                evidence_path=[ctx.source_kind, ctx.source_symbol, "constant_execution"],
                resolution="SAFE",
            )

        # Validated arguments or validated enums -> SAFE
        if ctx.is_argument_validated and ctx.shell_context == ShellContext.DIRECT_ARGV:
            return ProcessEvidence(
                category=ProcessFindingCategory.PROCESS_EXECUTION,
                root_cause="VALIDATED_ARGUMENT",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                library=ctx.library,
                operation=ctx.operation,
                shell_context=ctx.shell_context.value,
                shell_mode=ctx.shell_mode,
                argument_validation=True,
                sanitization_valid=True,
                capability=ctx.capability.value,
                impact="NONE",
                trust_boundary_crossed=False,
                evidence_path=[ctx.source_kind, ctx.source_symbol, "validated_argv"],
                resolution="SAFE",
            )

        # Validated shell sanitizer -> SAFE
        if ctx.sanitizer_valid_for_shell is True:
            return ProcessEvidence(
                category=ProcessFindingCategory.PROCESS_EXECUTION,
                root_cause="SANITIZED_SHELL_INPUT",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                library=ctx.library,
                operation=ctx.operation,
                shell_context=ctx.shell_context.value,
                shell_mode=ctx.shell_mode,
                argument_validation=True,
                sanitization_valid=True,
                capability=ctx.capability.value,
                impact="NONE",
                trust_boundary_crossed=False,
                evidence_path=[ctx.source_kind, ctx.source_symbol, "shell_escaped_input"],
                resolution="SAFE",
            )

        # INV-C7-07: Unknown shell context or unresolvable configuration -> UNKNOWN
        if ctx.shell_context == ShellContext.UNKNOWN:
            return ProcessEvidence(
                category=ProcessFindingCategory.PROCESS_EXECUTION,
                root_cause="UNKNOWN_SHELL_CONFIGURATION",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                library=ctx.library,
                operation=ctx.operation,
                shell_context=ShellContext.UNKNOWN.value,
                shell_mode=None,
                argument_validation=False,
                sanitization_valid=None,
                capability="UNKNOWN",
                impact="UNKNOWN",
                trust_boundary_crossed=True,
                evidence_path=[ctx.source_kind, ctx.source_symbol, "unknown_configuration"],
                resolution="UNKNOWN",
            )

        # C7.2 Shell Injection: Explicit sh/bash/cmd/powershell invocation
        if ctx.shell_context == ShellContext.EXPLICIT_SHELL:
            return ProcessEvidence(
                category=ProcessFindingCategory.SHELL_INJECTION,
                root_cause="SHELL_INJECTION",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                library=ctx.library,
                operation=ctx.operation,
                shell_context=ctx.shell_context.value,
                shell_mode=ctx.shell_mode,
                argument_validation=ctx.is_argument_validated,
                sanitization_valid=ctx.sanitizer_valid_for_shell,
                capability=ctx.capability.value,
                impact="PROCESS_SPAWN",
                trust_boundary_crossed=True,
                evidence_path=[
                    ctx.source_kind,
                    ctx.source_symbol,
                    ctx.library,
                    "EXPLICIT_SHELL",
                    ctx.capability.value,
                ],
                resolution="VULNERABLE",
            )

        # C7.1 Command Injection: shell=True / SHELL_INTERPRETED
        if ctx.shell_mode is True or ctx.shell_context == ShellContext.SHELL_INTERPRETED:
            return ProcessEvidence(
                category=ProcessFindingCategory.COMMAND_INJECTION,
                root_cause="COMMAND_INJECTION",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                library=ctx.library,
                operation=ctx.operation,
                shell_context=ShellContext.SHELL_INTERPRETED.value,
                shell_mode=True,
                argument_validation=ctx.is_argument_validated,
                sanitization_valid=ctx.sanitizer_valid_for_shell,
                capability=ctx.capability.value,
                impact="PROCESS_SPAWN",
                trust_boundary_crossed=True,
                evidence_path=[
                    ctx.source_kind,
                    ctx.source_symbol,
                    ctx.library,
                    "shell=True",
                    ctx.capability.value,
                ],
                resolution="VULNERABLE",
            )

        # C7.3 Argument Injection: shell=False + DIRECT_ARGV + untrusted argument
        # INV-C7-03: shell=False + argv-array execution MUST NOT be classified as shell injection!
        if ctx.shell_mode is False or ctx.shell_context == ShellContext.DIRECT_ARGV:
            return ProcessEvidence(
                category=ProcessFindingCategory.ARGUMENT_INJECTION,
                root_cause="ARGUMENT_INJECTION",
                source_kind=ctx.source_kind,
                source_symbol=ctx.source_symbol,
                library=ctx.library,
                operation=ctx.operation,
                shell_context=ShellContext.DIRECT_ARGV.value,
                shell_mode=False,
                argument_validation=False,
                sanitization_valid=ctx.sanitizer_valid_for_shell,
                capability=ctx.capability.value,
                impact="PROCESS_SPAWN",
                trust_boundary_crossed=True,
                evidence_path=[
                    ctx.source_kind,
                    ctx.source_symbol,
                    ctx.library,
                    "argv_array_unvalidated_argument",
                    ctx.capability.value,
                ],
                resolution="VULNERABLE",
            )

        return None
