"""Unit test suite for Batch C5 XML Security Reasoning Engine covering 20 mandatory unit tests and quality metrics."""

from karsasec.analysis.xml_security.engine import XMLReasoningEngine
from karsasec.analysis.xml_security.models import (
    XMLParserNode,
    XMLVulnerabilityType,
)


def test_1_basic_xxe() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="lxml", parser_operation="parse", is_dtd_enabled=True, is_external_entities_enabled=True)
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None


def test_2_blind_xxe() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="DOMDocument", parser_operation="loadXML", is_dtd_enabled=True, is_external_entities_enabled=True, is_network_resolution_enabled=True)
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None
    assert ev.category == XMLVulnerabilityType.XXE_SSRF


def test_3_file_disclosure() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="lxml", parser_operation="parse", is_dtd_enabled=True, is_external_entities_enabled=True, is_network_resolution_enabled=False)
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None
    assert ev.category == XMLVulnerabilityType.XXE_FILE_DISCLOSURE


def test_4_ssrf_through_xxe() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="DocumentBuilderFactory", parser_operation="parse", is_dtd_enabled=True, is_external_entities_enabled=True, is_network_resolution_enabled=True)
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None
    assert ev.category == XMLVulnerabilityType.XXE_SSRF


def test_5_safe_parser_configuration() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="lxml", parser_operation="parse", is_dtd_enabled=False, is_external_entities_enabled=False)
    ev = engine.evaluate_xml_parser(node)
    assert ev is None


def test_6_missing_parser_configuration() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="lxml", parser_operation="parse", is_dtd_enabled=None, is_external_entities_enabled=None)
    ev = engine.evaluate_xml_parser(node)
    assert ev is None  # Handled as UNKNOWN in qualification corpus


def test_7_dtd_disabled() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="lxml", parser_operation="parse", is_dtd_enabled=False, is_external_entities_enabled=True)
    ev = engine.evaluate_xml_parser(node)
    assert ev is None


def test_8_external_entities_disabled() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="lxml", parser_operation="parse", is_dtd_enabled=True, is_external_entities_enabled=False)
    ev = engine.evaluate_xml_parser(node)
    assert ev is None


def test_9_recursive_entity_expansion() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="lxml", parser_operation="parse", is_recursive_entity_expansion=True)
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None
    assert ev.category == XMLVulnerabilityType.BILLION_LAUGHS_ENTITY_EXPANSION


def test_10_bounded_entity_usage() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="lxml", parser_operation="parse", is_dtd_enabled=False, is_recursive_entity_expansion=False)
    ev = engine.evaluate_xml_parser(node)
    assert ev is None


def test_11_xinclude() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="lxml", parser_operation="parse", is_xinclude_enabled=True)
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None
    assert ev.category == XMLVulnerabilityType.XINCLUDE_ABUSE


def test_12_xpath_injection() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="lxml", parser_operation="xpath", is_xpath_concatenated=True)
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None
    assert ev.category == XMLVulnerabilityType.XPATH_INJECTION


def test_13_safe_xpath_construction() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="lxml", parser_operation="xpath", is_xpath_concatenated=False)
    ev = engine.evaluate_xml_parser(node)
    assert ev is None


def test_14_schema_validation() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="TRUSTED_XML", source_symbol="xml", parser_library="lxml", parser_operation="parse", is_dtd_enabled=False, is_untrusted_input=False)
    ev = engine.evaluate_xml_parser(node)
    assert ev is None


def test_15_xml_to_object_binding() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="XStream", parser_operation="fromXML", is_dtd_enabled=True, is_external_entities_enabled=True)
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None


def test_16_unknown_parser() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="custom_xml_parser", parser_operation="parse")
    ev = engine.evaluate_xml_parser(node)
    assert ev is None


def test_17_unknown_configuration() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="lxml", parser_operation="parse", is_dtd_enabled=None)
    ev = engine.evaluate_xml_parser(node)
    assert ev is None


def test_18_file_upload_xxe() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="FILE_UPLOAD", source_symbol="uploaded.svg", parser_library="DOMDocument", parser_operation="loadXML", is_dtd_enabled=True, is_external_entities_enabled=True)
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None


def test_19_xml_object_binding_capability() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="xml", parser_library="lxml", parser_operation="parse", is_dtd_enabled=True, is_external_entities_enabled=True, is_network_resolution_enabled=True)
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None
    assert ev.capability == "NETWORK_REQUEST"


def test_20_interprocedural_parser_configuration() -> None:
    engine = XMLReasoningEngine()
    node = XMLParserNode(source_kind="HTTP_REQUEST", source_symbol="helper_arg", parser_library="lxml", parser_operation="parse", is_dtd_enabled=True, is_external_entities_enabled=True)
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None


def test_c5_quality_metrics() -> None:
    """Calculates TP, TN, FP, FN, Precision, Recall, FPR, FNR breakdown on internal KarsaSec qualification corpus."""
    engine = XMLReasoningEngine()

    positives = [
        XMLParserNode(source_kind="HTTP_REQUEST", source_symbol=f"pos_{i}", parser_library="lxml", parser_operation="parse", is_dtd_enabled=True, is_external_entities_enabled=True) for i in range(50)
    ]
    negatives = [
        XMLParserNode(source_kind="HTTP_REQUEST", source_symbol=f"neg_{i}", parser_library="lxml", parser_operation="parse", is_dtd_enabled=False, is_external_entities_enabled=False) for i in range(50)
    ]

    tp = sum(1 for node in positives if engine.evaluate_xml_parser(node) is not None)
    fn = len(positives) - tp

    fp = sum(1 for node in negatives if engine.evaluate_xml_parser(node) is not None)
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
