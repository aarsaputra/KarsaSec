"""Data models for KarsaSec Server-Side Template Injection Security Reasoning Engine (Batch C6)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class SSTIVulnerabilityType(StrEnum):
    SSTI_COMMAND_EXECUTION = "SSTI_COMMAND_EXECUTION"
    SSTI_FILE_READ = "SSTI_FILE_READ"
    EXPRESSION_INJECTION = "EXPRESSION_INJECTION"
    TEMPLATE_FILE_INCLUSION = "TEMPLATE_FILE_INCLUSION"


class CapabilityClass(StrEnum):
    NONE = "NONE"
    PROCESS_SPAWN = "PROCESS_SPAWN"
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    NETWORK_REQUEST = "NETWORK_REQUEST"


@dataclass
class SSTINode:
    """Represents a template engine assembly node evaluated for SSTI, expression injection, and sandbox escapes."""

    source_kind: str  # HTTP_REQUEST, TEMPLATE_VARIABLE, TEMPLATE_SOURCE, TEMPLATE_FILE_PATH
    source_symbol: str
    template_engine: str  # Jinja2, Twig, FreeMarker, Velocity, Thymeleaf, ERB, Handlebars, Pug
    operation: str  # Template, render, render_string, compile
    is_user_controlled_source: bool = True
    is_sandbox_enabled: bool | None = None  # True, False, None (UNKNOWN)
    capability: CapabilityClass = CapabilityClass.NONE
    sink_symbol: str | None = None
    language: str = "python"  # python, java, php, javascript, ruby


@dataclass
class SSTIEvidence:
    """Machine-readable evidence output for SSTI Security findings."""

    category: SSTIVulnerabilityType
    source_kind: str
    source_symbol: str
    template_engine: str
    operation: str
    template_control: str
    sandbox_enabled: bool | None
    capability: str
    sink_symbol: str | None
    trust_boundary_crossed: bool
    evidence_path: list[str] = field(default_factory=list)
    resolution: str = "VULNERABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "source": {
                "kind": self.source_kind,
                "symbol": self.source_symbol,
            },
            "template_engine": {
                "library": self.template_engine,
                "operation": self.operation,
            },
            "template_control": self.template_control,
            "sandbox": {
                "enabled": self.sandbox_enabled,
                "verified": self.sandbox_enabled is True,
            },
            "capability": self.capability,
            "sink": self.sink_symbol,
            "trust_boundary_crossed": self.trust_boundary_crossed,
            "evidence_path": self.evidence_path,
            "resolution": self.resolution,
        }
