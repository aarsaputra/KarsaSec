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
                sarif_rules.append({
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
                })

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
                props["karsasec.verdict_confidence"] = v.confidence.value if hasattr(v.confidence, "value") else str(v.confidence)
                props["karsasec.evidence_fingerprint"] = v.evidence_fingerprint
                props["karsasec.reason_codes"] = [r.value if hasattr(r, "value") else str(r) for r in v.reason_codes]
                props["karsasec.provenance"] = list(v.provenance_path)

            sarif_results.append({
                "ruleId": finding.rule_id,
                "ruleIndex": rule_idx,
                "level": level,
                "message": {"text": finding.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {
                            "startLine": finding.evidence.line,
                            "startColumn": finding.evidence.column,
                            "snippet": {"text": finding.evidence.snippet},
                        },
                    },
                }],
                "partialFingerprints": {
                    "primaryLocationLineHash": finding.fingerprint,
                },
                "properties": props,
            })

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
            "runs": [{
                "tool": {
                    "driver": tool_driver,
                },
                "results": sarif_results,
            }],
        }

        content = json.dumps(sarif_payload, indent=2)
        target.write(content)
        target.close()
