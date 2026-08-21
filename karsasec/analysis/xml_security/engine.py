"""XML Security Reasoning Engine for Batch C5."""

from __future__ import annotations

from karsasec.analysis.xml_security.models import (
    XMLEvidence,
    XMLParserNode,
    XMLVulnerabilityType,
)


class XMLReasoningEngine:
    """Deterministic reasoning engine for XXE, XML entity expansion, XInclude, and XPath injection vulnerabilities."""

    SAFE_LIBRARIES = {"defusedxml"}

    def evaluate_xml_parser(self, node: XMLParserNode) -> XMLEvidence | None:
        """Evaluates XML parser configuration, dataflow, DTD/entity settings, and capabilities."""
        # Defused XML is universally safe
        if node.parser_library in self.SAFE_LIBRARIES:
            return None

        # Trusted XML source inputs with disabled DTD
        if not node.is_untrusted_input and node.is_dtd_enabled is False:
            return None

        # Explicitly disabled DTD & external entities -> SAFE
        if node.is_dtd_enabled is False and node.is_external_entities_enabled is False:
            return None

        # XPath Injection via String Concatenation
        if node.is_xpath_concatenated:
            return XMLEvidence(
                category=XMLVulnerabilityType.XPATH_INJECTION,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                parser_library=node.parser_library,
                parser_operation=node.parser_operation,
                dtd_enabled=node.is_dtd_enabled,
                external_entities_enabled=node.is_external_entities_enabled,
                network_resolution=node.is_network_resolution_enabled,
                capability="XPATH_EVALUATION",
                sink_symbol="xpath_evaluator",
                trust_boundary_crossed=True,
                evidence_path=[node.source_kind, node.source_symbol, "xpath_string_concatenation"],
                resolution="VULNERABLE",
            )

        # XInclude Abuse
        if node.is_xinclude_enabled and node.is_untrusted_input:
            return XMLEvidence(
                category=XMLVulnerabilityType.XINCLUDE_ABUSE,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                parser_library=node.parser_library,
                parser_operation=node.parser_operation,
                dtd_enabled=node.is_dtd_enabled,
                external_entities_enabled=node.is_external_entities_enabled,
                network_resolution=True,
                capability="FILE_READ",
                sink_symbol="xinclude_resolver",
                trust_boundary_crossed=True,
                evidence_path=[node.source_kind, node.source_symbol, "xinclude_enabled"],
                resolution="VULNERABLE",
            )

        # Billion Laughs / Recursive Entity Expansion
        if node.is_recursive_entity_expansion:
            return XMLEvidence(
                category=XMLVulnerabilityType.BILLION_LAUGHS_ENTITY_EXPANSION,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                parser_library=node.parser_library,
                parser_operation=node.parser_operation,
                dtd_enabled=node.is_dtd_enabled,
                external_entities_enabled=node.is_external_entities_enabled,
                network_resolution=False,
                capability="RESOURCE_EXHAUSTION",
                sink_symbol="xml_entity_expander",
                trust_boundary_crossed=True,
                evidence_path=[node.source_kind, node.source_symbol, "recursive_entity_expansion"],
                resolution="VULNERABLE",
            )

        # Unsafe XXE: DTD enabled + external entities enabled
        if node.is_dtd_enabled is True and node.is_external_entities_enabled is True and node.is_untrusted_input:
            if node.is_network_resolution_enabled:
                category = XMLVulnerabilityType.XXE_SSRF
                capability = "NETWORK_REQUEST"
            else:
                category = XMLVulnerabilityType.XXE_FILE_DISCLOSURE
                capability = "FILE_READ"

            return XMLEvidence(
                category=category,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                parser_library=node.parser_library,
                parser_operation=node.parser_operation,
                dtd_enabled=node.is_dtd_enabled,
                external_entities_enabled=node.is_external_entities_enabled,
                network_resolution=node.is_network_resolution_enabled,
                capability=capability,
                sink_symbol="external_entity_resolver",
                trust_boundary_crossed=True,
                evidence_path=[
                    node.source_kind,
                    node.source_symbol,
                    node.parser_library,
                    "DTD_ENABLED",
                    "EXTERNAL_ENTITY",
                    capability,
                ],
                resolution="VULNERABLE",
            )

        return None
