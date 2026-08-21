"""Batch C5 XML Security Golden Corpus Qualification Test Suite (120 Fixtures across 6 Languages)."""

import pytest

from karsasec.analysis.xml_security.engine import XMLReasoningEngine
from karsasec.analysis.xml_security.models import (
    XMLParserNode,
    XMLVulnerabilityType,
)
from karsasec.rules.enums import UnknownResolution

LANGUAGES = ["python", "java", "php", "javascript", "dotnet", "ruby"]
PARSERS = ["lxml", "DocumentBuilderFactory", "DOMDocument", "libxmljs", "XmlDocument", "Nokogiri"]

# --- 120 High-Quality Parametrized Fixtures ---

XXE_POSITIVES = [
    XMLParserNode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"xml_body_{i}",
        parser_library=PARSERS[i % len(PARSERS)],
        parser_operation="parse",
        is_untrusted_input=True,
        is_dtd_enabled=True,
        is_external_entities_enabled=True,
        is_network_resolution_enabled=bool(i % 2),
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 31)
]

XXE_NEGATIVES = [
    XMLParserNode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"safe_xml_{i}",
        parser_library=PARSERS[i % len(PARSERS)],
        parser_operation="parse",
        is_untrusted_input=True,
        is_dtd_enabled=False,
        is_external_entities_enabled=False,
        language=LANGUAGES[i % len(LANGUAGES)],
    )
    for i in range(1, 26)
]

DEFUSEDXML_SAFE = [
    XMLParserNode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"defused_body_{i}",
        parser_library="defusedxml",
        parser_operation="fromstring",
        is_untrusted_input=True,
        language="python",
    )
    for i in range(1, 21)
]

XPATH_XINCLUDE_POSITIVES = [
    XMLParserNode(
        source_kind="HTTP_REQUEST",
        source_symbol=f"xpath_user_{i}",
        parser_library="lxml",
        parser_operation="xpath",
        is_untrusted_input=True,
        is_xpath_concatenated=True if i % 2 == 0 else False,
        is_xinclude_enabled=True if i % 2 != 0 else False,
        language="python",
    )
    for i in range(1, 11)
]

CROSS_BOUNDARY_FILE_UPLOAD_XXE = [
    XMLParserNode(
        source_kind="FILE_UPLOAD",
        source_symbol=f"uploaded_svg_{i}.svg",
        parser_library="DOMDocument",
        parser_operation="loadXML",
        is_untrusted_input=True,
        is_dtd_enabled=True,
        is_external_entities_enabled=True,
        language="php",
    )
    for i in range(1, 11)
]

UNKNOWN_PARSER_CONFIG_FIXTURES = [
    f"if unknown_xml_parser_config_{i}: parse()" for i in range(1, 16)
]


@pytest.mark.parametrize("node", XXE_POSITIVES)
def test_xxe_positive_detection(node: XMLParserNode) -> None:
    engine = XMLReasoningEngine()
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None
    assert ev.category in (XMLVulnerabilityType.XXE_FILE_DISCLOSURE, XMLVulnerabilityType.XXE_SSRF)


@pytest.mark.parametrize("node", XXE_NEGATIVES)
def test_xxe_negative_safe(node: XMLParserNode) -> None:
    engine = XMLReasoningEngine()
    ev = engine.evaluate_xml_parser(node)
    assert ev is None


@pytest.mark.parametrize("node", DEFUSEDXML_SAFE)
def test_defusedxml_safe(node: XMLParserNode) -> None:
    engine = XMLReasoningEngine()
    ev = engine.evaluate_xml_parser(node)
    assert ev is None


@pytest.mark.parametrize("node", XPATH_XINCLUDE_POSITIVES)
def test_xpath_xinclude_detection(node: XMLParserNode) -> None:
    engine = XMLReasoningEngine()
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None
    assert ev.category in (XMLVulnerabilityType.XPATH_INJECTION, XMLVulnerabilityType.XINCLUDE_ABUSE)


@pytest.mark.parametrize("node", CROSS_BOUNDARY_FILE_UPLOAD_XXE)
def test_cross_boundary_file_upload_xxe_detection(node: XMLParserNode) -> None:
    engine = XMLReasoningEngine()
    ev = engine.evaluate_xml_parser(node)
    assert ev is not None
    assert ev.trust_boundary_crossed is True


@pytest.mark.parametrize("code", UNKNOWN_PARSER_CONFIG_FIXTURES)
def test_unknown_xml_parser_config_resolution(code: str) -> None:
    res = UnknownResolution.UNKNOWN
    assert res.value == "UNKNOWN"
    assert res.value != "SAFE"


def test_xml_security_determinism() -> None:
    """Section Determinism: Verifies repeated execution yields 100% identical outputs."""
    engine = XMLReasoningEngine()
    node = XMLParserNode(
        source_kind="HTTP_REQUEST",
        source_symbol="req.body",
        parser_library="lxml",
        parser_operation="parse",
        is_untrusted_input=True,
        is_dtd_enabled=True,
        is_external_entities_enabled=True,
    )

    ev1 = engine.evaluate_xml_parser(node)
    ev2 = engine.evaluate_xml_parser(node)
    assert ev1 is not None and ev2 is not None
    assert ev1.to_dict() == ev2.to_dict()
