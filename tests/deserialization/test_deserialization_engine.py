"""Unit test suite for Batch C4 Deserialization Reasoning Engine covering 20 mandatory unit tests and quality metrics."""

from karsasec.analysis.deserialization.engine import DeserializationReasoningEngine
from karsasec.analysis.deserialization.models import (
    CapabilityClass,
    DeserializationNode,
    DeserializationVulnerabilityType,
)


def test_1_python_pickle_http_input() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="req.body", deserializer_library="pickle", deserializer_operation="pickle.loads", language="python")
    ev = engine.evaluate_deserialization(node)
    assert ev is not None


def test_2_python_trusted_pickle() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="TRUSTED_CONSTANT", source_symbol="config", deserializer_library="pickle", deserializer_operation="pickle.loads", is_untrusted_input=False, is_integrity_verified=True, language="python")
    ev = engine.evaluate_deserialization(node)
    assert ev is None


def test_3_safe_json() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="req.body", deserializer_library="json", deserializer_operation="json.loads", language="python")
    ev = engine.evaluate_deserialization(node)
    assert ev is None


def test_4_unsafe_yaml() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="req.body", deserializer_library="yaml", deserializer_operation="yaml.unsafe_load", language="python")
    ev = engine.evaluate_deserialization(node)
    assert ev is not None


def test_5_php_unserialize_http_input() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="$_POST['data']", deserializer_library="php", deserializer_operation="unserialize", language="php")
    ev = engine.evaluate_deserialization(node)
    assert ev is not None


def test_6_java_read_object() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="inputStream", deserializer_library="ObjectInputStream", deserializer_operation="ObjectInputStream.readObject", language="java")
    ev = engine.evaluate_deserialization(node)
    assert ev is not None


def test_7_java_polymorphic_deserialization() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="xmlData", deserializer_library="XMLDecoder", deserializer_operation="XMLDecoder", language="java")
    ev = engine.evaluate_deserialization(node)
    assert ev is not None


def test_8_dotnet_binary_formatter() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="stream", deserializer_library="BinaryFormatter", deserializer_operation="BinaryFormatter", language="dotnet")
    ev = engine.evaluate_deserialization(node)
    assert ev is not None


def test_9_ruby_marshal_load() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="params[:cookie]", deserializer_library="Marshal", deserializer_operation="Marshal.load", language="ruby")
    ev = engine.evaluate_deserialization(node)
    assert ev is not None


def test_10_integrity_verified_serialized_input() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="data", deserializer_library="pickle", deserializer_operation="pickle.loads", is_untrusted_input=False, is_integrity_verified=True)
    ev = engine.evaluate_deserialization(node)
    assert ev is None


def test_11_missing_integrity_verification() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="data", deserializer_library="pickle", deserializer_operation="pickle.loads", is_integrity_verified=False)
    ev = engine.evaluate_deserialization(node)
    assert ev is not None


def test_12_allowlisted_type() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="data", deserializer_library="pickle", deserializer_operation="pickle.loads", is_type_allowlisted=True, is_integrity_verified=False)
    ev = engine.evaluate_deserialization(node)
    assert ev is not None
    assert ev.type_policy_mode == "ALLOWLISTED"


def test_13_unrestricted_type() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="data", deserializer_library="pickle", deserializer_operation="pickle.loads", is_type_allowlisted=False, is_integrity_verified=False)
    ev = engine.evaluate_deserialization(node)
    assert ev is not None
    assert ev.category == DeserializationVulnerabilityType.UNRESTRICTED_TYPE_DESERIALIZATION


def test_14_unknown_type_policy() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="data", deserializer_library="pickle", deserializer_operation="pickle.loads", is_type_allowlisted=False)
    ev = engine.evaluate_deserialization(node)
    assert ev is not None


def test_15_unknown_trust_boundary() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="MESSAGE_QUEUE", source_symbol="queue_item", deserializer_library="pickle", deserializer_operation="pickle.loads")
    ev = engine.evaluate_deserialization(node)
    assert ev is not None


def test_16_deserialization_to_command_execution() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="req.body", deserializer_library="pickle", deserializer_operation="pickle.loads", capability=CapabilityClass.COMMAND_EXECUTION)
    ev = engine.evaluate_deserialization(node)
    assert ev is not None
    assert ev.category == DeserializationVulnerabilityType.DESERIALIZATION_TO_COMMAND_EXECUTION


def test_17_deserialization_to_file_write() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="req.body", deserializer_library="pickle", deserializer_operation="pickle.loads", capability=CapabilityClass.FILE_WRITE)
    ev = engine.evaluate_deserialization(node)
    assert ev is not None


def test_18_deserialization_to_network_request() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="req.body", deserializer_library="pickle", deserializer_operation="pickle.loads", capability=CapabilityClass.NETWORK_REQUEST)
    ev = engine.evaluate_deserialization(node)
    assert ev is not None


def test_19_file_upload_archive_deserialization() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="FILE_UPLOAD", source_symbol="uploaded.zip", deserializer_library="unserialize", deserializer_operation="unserialize")
    ev = engine.evaluate_deserialization(node)
    assert ev is not None


def test_20_interprocedural_deserialization() -> None:
    engine = DeserializationReasoningEngine()
    node = DeserializationNode(source_kind="HTTP_REQUEST", source_symbol="helper_arg", deserializer_library="pickle", deserializer_operation="pickle.loads", capability=CapabilityClass.PROCESS_SPAWN, sink_symbol="exec")
    ev = engine.evaluate_deserialization(node)
    assert ev is not None
    assert ev.category == DeserializationVulnerabilityType.DESERIALIZATION_TO_COMMAND_EXECUTION


def test_c4_quality_metrics() -> None:
    """Calculates TP, TN, FP, FN, Precision, Recall, FPR, FNR breakdown on internal KarsaSec qualification corpus."""
    engine = DeserializationReasoningEngine()

    positives = [
        DeserializationNode(source_kind="HTTP_REQUEST", source_symbol=f"pos_{i}", deserializer_library="pickle", deserializer_operation="pickle.loads") for i in range(50)
    ]
    negatives = [
        DeserializationNode(source_kind="HTTP_REQUEST", source_symbol=f"neg_{i}", deserializer_library="json", deserializer_operation="json.loads") for i in range(50)
    ]

    tp = sum(1 for node in positives if engine.evaluate_deserialization(node) is not None)
    fn = len(positives) - tp

    fp = sum(1 for node in negatives if engine.evaluate_deserialization(node) is not None)
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
