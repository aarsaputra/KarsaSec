"""Data models for KarsaSec Command Injection & OS Process Capability Reasoning Engine (Batch C7)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ShellContext(StrEnum):
    DIRECT_ARGV = "DIRECT_ARGV"
    SHELL_INTERPRETED = "SHELL_INTERPRETED"
    EXPLICIT_SHELL = "EXPLICIT_SHELL"
    UNKNOWN = "UNKNOWN"


class ProcessCapability(StrEnum):
    NONE = "NONE"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    PROCESS_SPAWN = "PROCESS_SPAWN"
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    NETWORK_REQUEST = "NETWORK_REQUEST"
    UNKNOWN = "UNKNOWN"


class ProcessFindingCategory(StrEnum):
    COMMAND_INJECTION = "COMMAND_INJECTION"
    SHELL_INJECTION = "SHELL_INJECTION"
    ARGUMENT_INJECTION = "ARGUMENT_INJECTION"
    UNSAFE_PROCESS_CONSTRUCTION = "UNSAFE_PROCESS_CONSTRUCTION"
    PROCESS_CAPABILITY_EXPOSURE = "PROCESS_CAPABILITY_EXPOSURE"
    PROCESS_EXECUTION = "PROCESS_EXECUTION"


@dataclass
class ProcessExecutionContext:
    """Represents a process execution context evaluated for command injection and argument injection."""

    source_kind: str  # HTTP_REQUEST, FILE_UPLOAD, TRUSTED_CONSTANT, DATABASE_RECORD
    source_symbol: str
    library: str  # subprocess, os, child_process, exec, ProcessBuilder, Process
    operation: str  # run, system, exec, spawn, Command, Start
    shell_context: ShellContext = ShellContext.UNKNOWN
    shell_mode: bool | None = None  # True, False, None (UNKNOWN)
    is_user_controlled: bool = True
    is_argument_validated: bool = False
    sanitizer_valid_for_shell: bool | None = None  # True, False, None (UNKNOWN)
    capability: ProcessCapability = ProcessCapability.PROCESS_SPAWN
    sink_symbol: str = "process_sink"
    language: str = "python"  # python, javascript, php, java, go, ruby, dotnet


@dataclass
class ProcessEvidence:
    """Machine-readable evidence output for Process Capability and Command Injection findings."""

    category: ProcessFindingCategory
    root_cause: str
    source_kind: str
    source_symbol: str
    library: str
    operation: str
    shell_context: str
    shell_mode: bool | None
    argument_validation: bool
    sanitization_valid: bool | None
    capability: str
    impact: str
    trust_boundary_crossed: bool
    evidence_path: list[str] = field(default_factory=list)
    resolution: str = "VULNERABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "root_cause": self.root_cause,
            "source": {
                "kind": self.source_kind,
                "symbol": self.source_symbol,
            },
            "transformations": [
                "string_concatenation"
            ],
            "process_sink": {
                "library": self.library,
                "operation": self.operation,
            },
            "shell_context": self.shell_context,
            "shell_mode": self.shell_mode,
            "sanitization": {
                "present": self.sanitization_valid is not None,
                "valid_for_context": self.sanitization_valid is True,
            },
            "argument_validation": self.argument_validation,
            "capability": self.capability,
            "impact": self.impact,
            "trust_boundary_crossed": self.trust_boundary_crossed,
            "evidence_path": self.evidence_path,
            "resolution": self.resolution,
        }
