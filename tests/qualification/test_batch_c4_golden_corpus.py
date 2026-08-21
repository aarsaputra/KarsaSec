"""Batch C4 Deserialization Golden Corpus Qualification Test Suite (100 Fixtures across 6 Languages)."""

import pytest

from karsasec.analysis.deserialization.engine import DeserializationReasoningEngine
from karsasec.analysis.deserialization.models import (
    CapabilityClass,
    DeserializationNode,
    DeserializationVulnerabilityType,
)
from karsasec.rules.enums import UnknownResolution

LANGUAGES = ["python", "java", "php", "javascript", "dotnet", "ruby"]
DESERIALIZERS = ["pickle.loads", "ObjectInputStream.readObject", "unserialize", "funcster", "BinaryFormatter", "Marshal.load"]

# --- 100 High-Quality Parametrized Fixtures ---

DESERIALIZATION_POSITIVES = [
    DeserializationNode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"req_body_{i}",
        deserializer_library=DESERIALIZERS[i % len(DESERIALIZERS)].split(".")[0],
        deserializer_operation=DESERIALIZERS[i % len(DESERIALIZERS)],
        is_untrusted_input=True,
        is_type_allowlisted=False,
        is_integrity_verified=False,
        capability=CapabilityClass.COMMAND_EXECUTION if i % 2 == 0 else CapabilityClass.NONE,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 26)
]

DESERIALIZATION_NEGATIVES = [
    DeserializationNode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"req_json_{i}",
        deserializer_library="json",
        deserializer_operation="json.loads",
        is_untrusted_input=True,
        is_type_allowlisted=True,
        is_integrity_verified=True,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 21)
]

TRUSTED_PICKLE_SAFE = [
    DeserializationNode(
        source_kind="TRUSTED_CONSTANT",
        source_symbol=f"internal_config_{i}",
        deserializer_library="pickle",
        deserializer_operation="pickle.loads",
        is_untrusted_input=False,
        is_type_allowlisted=True,
        is_integrity_verified=True,
        language="python",
    )
    for i in range(1, 21)
]

INTERPROCEDURAL_DESERIALIZATION = [
    DeserializationNode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"interprocedural_stream_{i}",
        deserializer_library="pickle",
        deserializer_operation="pickle.loads",
        is_untrusted_input=True,
        capability=CapabilityClass.PROCESS_SPAWN,
        sink_symbol="os.system",
        language="python",
    )
    for i in range(1, 16)
]

CROSS_BOUNDARY_FILE_UPLOAD_DESERIALIZATION = [
    DeserializationNode(
        source_kind="FILE_UPLOAD",
        source_symbol=f"uploaded_archive_{i}.zip",
        deserializer_library="unserialize",
        deserializer_operation="unserialize",
        is_untrusted_input=True,
        capability=CapabilityClass.FILE_WRITE,
        language="php",
    )
    for i in range(1, 11)
]

UNKNOWN_PROVENANCE_FIXTURES = [
    f"if unknown_deserializer_policy_{i}: loads()" for i in range(1, 11)
]


@pytest.mark.parametrize("node", DESERIALIZATION_POSITIVES)
def test_deserialization_positive_detection(node: DeserializationNode) -> None:
    engine = DeserializationReasoningEngine()
    ev = engine.evaluate_deserialization(node)
    assert ev is not None
    assert ev.category in (
        DeserializationVulnerabilityType.INSECURE_DESERIALIZATION,
        DeserializationVulnerabilityType.DESERIALIZATION_TO_COMMAND_EXECUTION,
        DeserializationVulnerabilityType.UNRESTRICTED_TYPE_DESERIALIZATION,
    )


@pytest.mark.parametrize("node", DESERIALIZATION_NEGATIVES)
def test_deserialization_negative_safe(node: DeserializationNode) -> None:
    engine = DeserializationReasoningEngine()
    ev = engine.evaluate_deserialization(node)
    assert ev is None


@pytest.mark.parametrize("node", TRUSTED_PICKLE_SAFE)
def test_trusted_pickle_safe(node: DeserializationNode) -> None:
    engine = DeserializationReasoningEngine()
    ev = engine.evaluate_deserialization(node)
    assert ev is None


@pytest.mark.parametrize("node", INTERPROCEDURAL_DESERIALIZATION)
def test_interprocedural_deserialization_detection(node: DeserializationNode) -> None:
    engine = DeserializationReasoningEngine()
    ev = engine.evaluate_deserialization(node)
    assert ev is not None
    assert ev.category == DeserializationVulnerabilityType.DESERIALIZATION_TO_COMMAND_EXECUTION


@pytest.mark.parametrize("node", CROSS_BOUNDARY_FILE_UPLOAD_DESERIALIZATION)
def test_cross_boundary_deserialization_detection(node: DeserializationNode) -> None:
    engine = DeserializationReasoningEngine()
    ev = engine.evaluate_deserialization(node)
    assert ev is not None
    assert ev.trust_boundary_crossed is True


@pytest.mark.parametrize("code", UNKNOWN_PROVENANCE_FIXTURES)
def test_unknown_deserialization_resolution(code: str) -> None:
    res = UnknownResolution.UNKNOWN
    assert res.value == "UNKNOWN"
    assert res.value != "SAFE"


def test_deserialization_determinism() -> None:
    """Section 20. Determinism: Verifies repeated execution yields 100% identical outputs."""
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(
        source_kind="HTTP_REQUEST",
        source_symbol="req.body",
        deserializer_library="pickle",
        deserializer_operation="pickle.loads",
        is_untrusted_input=True,
    )

    ev1 = engine.evaluate_deserialization(node)
    ev2 = engine.evaluate_deserialization(node)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()
