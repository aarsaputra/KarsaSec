"""Data models for KarsaSec Deserialization Security Reasoning Engine (Batch C4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class DeserializationVulnerabilityType(StrEnum):
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    DESERIALIZATION_TO_COMMAND_EXECUTION = "DESERIALIZATION_TO_COMMAND_EXECUTION"
    MISSING_INTEGRITY_VERIFICATION = "MISSING_INTEGRITY_VERIFICATION"
    UNRESTRICTED_TYPE_DESERIALIZATION = "UNRESTRICTED_TYPE_DESERIALIZATION"


class CapabilityClass(StrEnum):
    NONE = "NONE"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    FILE_WRITE = "FILE_WRITE"
    FILE_READ = "FILE_READ"
    NETWORK_REQUEST = "NETWORK_REQUEST"
    PROCESS_SPAWN = "PROCESS_SPAWN"


@dataclass
class DeserializationNode:
    """Represents a serialized input node evaluated for insecure object reconstruction."""

    source_kind: str  # HTTP_REQUEST, MESSAGE_QUEUE, FILE_UPLOAD, TRUSTED_CONSTANT, DATABASE
    source_symbol: str
    deserializer_library: str  # pickle, yaml, unserialize, ObjectInputStream, BinaryFormatter, Marshal
    deserializer_operation: str  # pickle.loads, yaml.unsafe_load, unserialize, readObject
    is_untrusted_input: bool = True
    is_type_allowlisted: bool = False
    is_integrity_verified: bool = False
    capability: CapabilityClass = CapabilityClass.NONE
    sink_symbol: str | None = None
    language: str = "python"  # python, java, php, javascript, dotnet, ruby


@dataclass
class DeserializationEvidence:
    """Machine-readable evidence output for Deserialization Security findings."""

    category: DeserializationVulnerabilityType
    source_kind: str
    source_symbol: str
    deserializer_library: str
    deserializer_operation: str
    type_policy_mode: str
    has_allowlist: bool
    integrity_verified: bool
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
            "transformations": [
                "base64_decode"
            ],
            "deserializer": {
                "library": self.deserializer_library,
                "operation": self.deserializer_operation,
            },
            "type_policy": {
                "mode": self.type_policy_mode,
                "allowlist": self.has_allowlist,
            },
            "integrity": {
                "verified": self.integrity_verified,
                "mechanism": "HMAC" if self.integrity_verified else None,
            },
            "capability": self.capability,
            "sink": self.sink_symbol,
            "trust_boundary_crossed": self.trust_boundary_crossed,
            "evidence_path": self.evidence_path,
            "resolution": self.resolution,
        }
