"""Data models for KarsaSec XML Security Reasoning Engine (Batch C5)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class XMLVulnerabilityType(StrEnum):
    XXE_FILE_DISCLOSURE = "XXE_FILE_DISCLOSURE"
    XXE_SSRF = "XXE_SSRF"
    BLIND_XXE = "BLIND_XXE"
    BILLION_LAUGHS_ENTITY_EXPANSION = "BILLION_LAUGHS_ENTITY_EXPANSION"
    XPATH_INJECTION = "XPATH_INJECTION"
    XINCLUDE_ABUSE = "XINCLUDE_ABUSE"
    UNSAFE_XML_PARSER_CONFIG = "UNSAFE_XML_PARSER_CONFIG"


@dataclass
class XMLParserNode:
    """Represents an XML parser node evaluated for XXE, DTD, XInclude, and entity expansion security."""

    source_kind: str  # HTTP_REQUEST, FILE_UPLOAD, MESSAGE_QUEUE, TRUSTED_XML
    source_symbol: str
    parser_library: str  # lxml, etree, defusedxml, DocumentBuilderFactory, DOMDocument, XmlReader, Nokogiri
    parser_operation: str  # parse, fromstring, read, loadXML
    is_untrusted_input: bool = True
    is_dtd_enabled: bool | None = None  # True, False, None (UNKNOWN)
    is_external_entities_enabled: bool | None = None  # True, False, None (UNKNOWN)
    is_network_resolution_enabled: bool | None = None
    is_xinclude_enabled: bool = False
    is_recursive_entity_expansion: bool = False
    is_xpath_concatenated: bool = False
    language: str = "python"  # python, java, php, javascript, dotnet, ruby


@dataclass
class XMLEvidence:
    """Machine-readable evidence output for XML Security findings."""

    category: XMLVulnerabilityType
    source_kind: str
    source_symbol: str
    parser_library: str
    parser_operation: str
    dtd_enabled: bool | None
    external_entities_enabled: bool | None
    network_resolution: bool | None
    capability: str
    sink_symbol: str
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
            "parser": {
                "library": self.parser_library,
                "operation": self.parser_operation,
            },
            "configuration": {
                "dtd_enabled": self.dtd_enabled,
                "external_entities_enabled": self.external_entities_enabled,
                "network_resolution": self.network_resolution,
            },
            "capability": self.capability,
            "sink": self.sink_symbol,
            "trust_boundary_crossed": self.trust_boundary_crossed,
            "evidence_path": self.evidence_path,
            "resolution": self.resolution,
        }
