"""SARIFReporter generating compliant SARIF 2.1.0 format with rule taxonomy deduplication."""

import json

from karsasec.core.execution.result import ExecutionResult
from karsasec.core.finding.collection import FindingCollection
from karsasec.core.reporting.mapping import SARIF_SCORE_MAP, SARIF_SEVERITY_MAP
from karsasec.core.reporting.reporter import Reporter
from karsasec.core.reporting.target import ReportTarget


class SARIFReporter(Reporter):
    """Generates standard SARIF 2.1.0 security reports for GitHub Security & CI/CD integration."""

    def generate(self, result: ExecutionResult, target: ReportTarget) -> None:
        collection = FindingCollection(result.findings)

        # 1. Deduplicate Rules for tool.driver.rules
        rule_registry: dict[str, int] = {}
        sarif_rules: list[dict] = []

        for finding in collection.findings:
            if finding.rule_id not in rule_registry:
                rule_idx = len(sarif_rules)
                rule_registry[finding.rule_id] = rule_idx

                score = SARIF_SCORE_MAP.get(finding.severity, 5.0)
                sarif_rules.append(
                    {
                        "id": finding.rule_id,
                        "name": finding.title,
                        "shortDescription": {"text": finding.title},
                        "fullDescription": {"text": finding.description},
                        "help": {"text": f"{finding.description}\n\nRemediation:\n{finding.remediation}"},
                        "properties": {
                            "cwe": [finding.cwe_id],
                            "owasp": [finding.owasp],
                            "precision": finding.confidence.name.lower(),
                            "security-severity": f"{score:.1f}",
                        },
                    }
                )

        # 2. Build SARIF Results
        sarif_results: list[dict] = []
        for finding in collection.findings:
            rule_idx = rule_registry[finding.rule_id]
            level = SARIF_SEVERITY_MAP.get(finding.severity, "warning")
            uri = str(finding.file_path).replace("\\", "/")

            props = {
                "finding_id": finding.finding_id,
                "remediation": finding.remediation,
            }
            if getattr(finding, "verdict", None) is not None:
                v = finding.verdict
                props["karsasec.verdict"] = v.status.value if hasattr(v.status, "value") else str(v.status)
                props["karsasec.verdict_confidence"] = (
                    v.confidence.value if hasattr(v.confidence, "value") else str(v.confidence)
                )
                props["karsasec.evidence_fingerprint"] = v.evidence_fingerprint
                props["karsasec.reason_codes"] = [r.value if hasattr(r, "value") else str(r) for r in v.reason_codes]
                props["karsasec.provenance"] = list(v.provenance_path)

            if isinstance(finding.metadata, dict) and "explanation_fingerprint" in finding.metadata:
                props["karsasec.ai.explanation_available"] = True
                props["karsasec.ai.explanation_fingerprint"] = finding.metadata["explanation_fingerprint"]
                props["karsasec.ai.explanation_schema_version"] = finding.metadata.get(
                    "explanation_schema_version", "v1.0"
                )

            if isinstance(finding.metadata, dict) and "rca_fingerprint" in finding.metadata:
                props["karsasec.ai.rca_available"] = True
                props["karsasec.ai.rca_fingerprint"] = finding.metadata["rca_fingerprint"]
                props["karsasec.ai.root_cause_category"] = finding.metadata.get(
                    "root_cause_category", "UNKNOWN_ROOT_CAUSE"
                )
                props["karsasec.ai.evidence_completeness"] = finding.metadata.get("evidence_completeness", "PROVEN")
                props["karsasec.ai.fp_risk"] = finding.metadata.get("fp_risk", "HIGH_RISK")

            if isinstance(finding.metadata, dict) and "remediation_fingerprint" in finding.metadata:
                props["karsasec.ai.remediation_available"] = True
                props["karsasec.ai.remediation_fingerprint"] = finding.metadata["remediation_fingerprint"]
                props["karsasec.ai.strategy_type"] = finding.metadata.get("strategy_type", "UNKNOWN_REMEDIATION")

            if isinstance(finding.metadata, dict) and "patch_fingerprint" in finding.metadata:
                props["karsasec.ai.patch_proposal_available"] = True
                props["karsasec.ai.patch_validation_status"] = finding.metadata.get(
                    "patch_validation_status", "REQUIRES_HUMAN_REVIEW"
                )
                props["karsasec.ai.patch_fingerprint"] = finding.metadata["patch_fingerprint"]

            if isinstance(finding.metadata, dict) and "patch_application_status" in finding.metadata:
                props["karsasec.ai.patch_application_available"] = True
                props["karsasec.ai.patch_application_status"] = finding.metadata["patch_application_status"]
                props["karsasec.ai.approval_token_id"] = finding.metadata.get("approval_token_id", "N/A")
                props["karsasec.ai.application_transaction_id"] = finding.metadata.get(
                    "application_transaction_id", "N/A"
                )
                props["karsasec.ai.post_apply_verification_status"] = finding.metadata.get(
                    "post_apply_verification_status", "UNVERIFIED"
                )
                props["karsasec.ai.rollback_status"] = finding.metadata.get("rollback_status", "NOT_NEEDED")

            if isinstance(finding.metadata, dict):
                if "remediation_state" in finding.metadata:
                    props["karsasec.ai.remediation_state"] = str(finding.metadata["remediation_state"])
                if "lifecycle_fingerprint" in finding.metadata:
                    props["karsasec.ai.lifecycle_fingerprint"] = str(finding.metadata["lifecycle_fingerprint"])
                if "provenance_fingerprint" in finding.metadata:
                    props["karsasec.ai.provenance_fingerprint"] = str(finding.metadata["provenance_fingerprint"])
                if "verification_run_id" in finding.metadata:
                    props["karsasec.ai.verification_run_id"] = str(finding.metadata["verification_run_id"])
                if "verification_status" in finding.metadata:
                    props["karsasec.ai.verification_status"] = str(finding.metadata["verification_status"])

            sarif_results.append(
                {
                    "ruleId": finding.rule_id,
                    "ruleIndex": rule_idx,
                    "level": level,
                    "message": {"text": finding.description},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                "region": {
                                    "startLine": finding.evidence.line,
                                    "startColumn": finding.evidence.column,
                                    "snippet": {"text": finding.evidence.snippet},
                                },
                            },
                        }
                    ],
                    "partialFingerprints": {
                        "primaryLocationLineHash": finding.fingerprint,
                    },
                    "properties": props,
                }
            )

        # 3. Assemble SARIF 2.1.0 Object
        tool_driver = {
            "name": "KarsaSec",
            "semanticVersion": "0.1.0",
            "rules": sarif_rules,
        }

        if result.rag_context:
            tool_driver["properties"] = {"rag_context": [dict(ctx) for ctx in result.rag_context]}

        sarif_payload = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": tool_driver,
                    },
                    "results": sarif_results,
                }
            ],
        }

        content = json.dumps(sarif_payload, indent=2)
        target.write(content)
        target.close()
