"""SSTI Security Reasoning Engine for Batch C6."""

from __future__ import annotations

from karsasec.analysis.ssti.models import (
    CapabilityClass,
    SSTIEvidence,
    SSTINode,
    SSTIVulnerabilityType,
)


class SSTIReasoningEngine:
    """Deterministic reasoning engine for Server-Side Template Injection vulnerabilities."""

    def evaluate_template_assembly(self, node: SSTINode) -> SSTIEvidence | None:
        """Evaluates template assembly, source control, sandbox settings, and capabilities."""
        # Safe template variable passing (e.g. render_template("index.html", var=user_input))
        if node.source_kind == "TEMPLATE_VARIABLE" and not node.is_user_controlled_source:
            return None

        # Template File Inclusion (user-controlled template name/path)
        if node.source_kind == "TEMPLATE_FILE_PATH" and node.is_user_controlled_source:
            return SSTIEvidence(
                category=SSTIVulnerabilityType.TEMPLATE_FILE_INCLUSION,
                source_kind=node.source_kind,
                source_symbol=node.source_symbol,
                template_engine=node.template_engine,
                operation=node.operation,
                template_control="USER_CONTROLLED_PATH",
                sandbox_enabled=node.is_sandbox_enabled,
                capability="FILE_READ",
                sink_symbol="template_loader",
                trust_boundary_crossed=True,
                evidence_path=[node.source_kind, node.source_symbol, "template_loader_path"],
                resolution="VULNERABLE",
            )

        # Untrusted Template Source Assembly (e.g., Template(user_input).render())
        if node.source_kind in ("HTTP_REQUEST", "TEMPLATE_SOURCE") and node.is_user_controlled_source:
            # Sandbox enabled -> SAFE
            if node.is_sandbox_enabled is True:
                return None

            # Capability correlation: Process Spawn / Command Execution
            if node.capability == CapabilityClass.PROCESS_SPAWN:
                return SSTIEvidence(
                    category=SSTIVulnerabilityType.SSTI_COMMAND_EXECUTION,
                    source_kind=node.source_kind,
                    source_symbol=node.source_symbol,
                    template_engine=node.template_engine,
                    operation=node.operation,
                    template_control="USER_CONTROLLED",
                    sandbox_enabled=node.is_sandbox_enabled,
                    capability=node.capability.value,
                    sink_symbol=node.sink_symbol or "PROCESS_SPAWN",
                    trust_boundary_crossed=True,
                    evidence_path=[
                        node.source_kind,
                        node.source_symbol,
                        node.template_engine,
                        "template_source_assembly",
                        node.capability.value,
                    ],
                    resolution="VULNERABLE",
                )

            # Capability correlation: Arbitrary File Read
            if node.capability == CapabilityClass.FILE_READ:
                return SSTIEvidence(
                    category=SSTIVulnerabilityType.SSTI_FILE_READ,
                    source_kind=node.source_kind,
                    source_symbol=node.source_symbol,
                    template_engine=node.template_engine,
                    operation=node.operation,
                    template_control="USER_CONTROLLED",
                    sandbox_enabled=node.is_sandbox_enabled,
                    capability=node.capability.value,
                    sink_symbol=node.sink_symbol or "FILE_READ",
                    trust_boundary_crossed=True,
                    evidence_path=[
                        node.source_kind,
                        node.source_symbol,
                        node.template_engine,
                        "template_source_assembly",
                        node.capability.value,
                    ],
                    resolution="VULNERABLE",
                )

            # Expression Injection
            if node.is_sandbox_enabled is False:
                return SSTIEvidence(
                    category=SSTIVulnerabilityType.EXPRESSION_INJECTION,
                    source_kind=node.source_kind,
                    source_symbol=node.source_symbol,
                    template_engine=node.template_engine,
                    operation=node.operation,
                    template_control="USER_CONTROLLED",
                    sandbox_enabled=False,
                    capability="EXPRESSION_EVALUATION",
                    sink_symbol="template_expression_evaluator",
                    trust_boundary_crossed=True,
                    evidence_path=[
                        node.source_kind,
                        node.source_symbol,
                        node.template_engine,
                        "sandbox_disabled",
                    ],
                    resolution="VULNERABLE",
                )

        return None
