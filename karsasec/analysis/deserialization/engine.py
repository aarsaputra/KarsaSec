"""Deserialization Security Reasoning Engine for Batch C4."""

from __future__ import annotations

from karsasec.analysis.deserialization.models import (
    CapabilityClass,
    DeserializationEvidence,
    DeserializationNode,
    DeserializationVulnerabilityType,
)


class DeserializationReasoningEngine:
    """Deterministic reasoning engine for insecure deserialization vulnerabilities."""

    UNSAFE_DESERIALIZERS = {
        "pickle.loads", "pickle.load", "marshal.loads", "yaml.unsafe_load", "yaml.load",
        "unserialize", "ObjectInputStream.readObject", "XMLDecoder", "XStream",
        "BinaryFormatter", "NetDataContractSerializer", "Marshal.load", "funcster", "serialize-javascript",
    }

    SAFE_DESERIALIZERS = {"json.loads", "yaml.safe_load", "JSON.parse", "json_decode"}

    def evaluate_deserialization(self, node: DeserializationNode) -> DeserializationEvidence | None:
        """Evaluates deserialization security over dataflow, integrity, type policy, and capabilities."""
        # Safe deserializers (json.loads, safe_load, etc.)
        if node.deserializer_operation in self.SAFE_DESERIALIZERS:
            return None

        # Trusted source inputs (constants, internal config with integrity)
        if not node.is_untrusted_input and node.is_integrity_verified:
            return None

        # Check if deserializer is in unsafe list
        if node.deserializer_operation in self.UNSAFE_DESERIALIZERS:
            # Integrity reasoning: missing integrity verification
            if not node.is_integrity_verified and node.is_untrusted_input:
                # Capability correlation: Deserialization to Command Execution
                if node.capability in (CapabilityClass.COMMAND_EXECUTION, CapabilityClass.PROCESS_SPAWN):
                    return DeserializationEvidence(
                        category=DeserializationVulnerabilityType.DESERIALIZATION_TO_COMMAND_EXECUTION,
                        source_kind=node.source_kind,
                        source_symbol=node.source_symbol,
                        deserializer_library=node.deserializer_library,
                        deserializer_operation=node.deserializer_operation,
                        type_policy_mode="UNRESTRICTED" if not node.is_type_allowlisted else "ALLOWLISTED",
                        has_allowlist=node.is_type_allowlisted,
                        integrity_verified=node.is_integrity_verified,
                        capability=node.capability.value,
                        sink_symbol=node.sink_symbol or "PROCESS_SPAWN",
                        trust_boundary_crossed=True,
                        evidence_path=[
                            node.source_kind,
                            node.source_symbol,
                            node.deserializer_operation,
                            "object_reconstruction",
                            node.capability.value,
                        ],
                        resolution="VULNERABLE",
                    )

                # Unrestricted Type Deserialization
                if not node.is_type_allowlisted:
                    return DeserializationEvidence(
                        category=DeserializationVulnerabilityType.UNRESTRICTED_TYPE_DESERIALIZATION,
                        source_kind=node.source_kind,
                        source_symbol=node.source_symbol,
                        deserializer_library=node.deserializer_library,
                        deserializer_operation=node.deserializer_operation,
                        type_policy_mode="UNRESTRICTED",
                        has_allowlist=False,
                        integrity_verified=node.is_integrity_verified,
                        capability=node.capability.value,
                        sink_symbol=node.sink_symbol,
                        trust_boundary_crossed=True,
                        evidence_path=[
                            node.source_kind,
                            node.source_symbol,
                            node.deserializer_operation,
                            "polymorphic_object_construction",
                        ],
                        resolution="VULNERABLE",
                    )

                # Insecure Deserialization
                return DeserializationEvidence(
                    category=DeserializationVulnerabilityType.INSECURE_DESERIALIZATION,
                    source_kind=node.source_kind,
                    source_symbol=node.source_symbol,
                    deserializer_library=node.deserializer_library,
                    deserializer_operation=node.deserializer_operation,
                    type_policy_mode="UNRESTRICTED" if not node.is_type_allowlisted else "ALLOWLISTED",
                    has_allowlist=node.is_type_allowlisted,
                    integrity_verified=False,
                    capability=node.capability.value,
                    sink_symbol=node.sink_symbol,
                    trust_boundary_crossed=True,
                    evidence_path=[
                        node.source_kind,
                        node.source_symbol,
                        node.deserializer_operation,
                    ],
                    resolution="VULNERABLE",
                )

        return None
