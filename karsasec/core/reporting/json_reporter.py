"""JSONReporter producing structured KarsaSec v1.0 JSON report."""

import json

from karsasec.core.execution.result import ExecutionResult
from karsasec.core.finding.collection import FindingCollection
from karsasec.core.reporting.models import ReportMetadata
from karsasec.core.reporting.reporter import Reporter
from karsasec.core.reporting.target import ReportTarget


class JSONReporter(Reporter):
    """Generates structured KarsaSec v1.0 JSON reports."""

    def generate(self, result: ExecutionResult, target: ReportTarget) -> None:
        collection = FindingCollection(result.findings)
        meta = ReportMetadata(
            scan_id=result.scan_id,
            timestamp=result.timestamp,
            duration_ms=result.execution_time_ms,
            files_scanned=result.files_scanned,
            rules_checked=result.rules_checked,
        )

        sev_summary = {sev.name: count for sev, count in collection.severity_summary.items()}

        findings_payload = []
        for f in collection.findings:
            findings_payload.append({
                "finding_id": f.finding_id,
                "rule_id": f.rule_id,
                "fingerprint": f.fingerprint,
                "title": f.title,
                "severity": f.severity.name,
                "confidence": f.confidence.name,
                "cwe_id": f.cwe_id,
                "owasp": f.owasp,
                "file_path": str(f.file_path).replace("\\", "/"),
                "location": {
                    "line": f.evidence.line,
                    "column": f.evidence.column,
                },
                "evidence": {
                    "snippet": f.evidence.snippet,
                    "context_lines": list(f.evidence.context_lines),
                },
                "description": f.description,
                "remediation": f.remediation,
                "rule_version": f.rule_version,
            })

        report_dict = {
            "metadata": {
                "schema_version": meta.schema_version,
                "scanner_name": meta.scanner_name,
                "scanner_version": meta.scanner_version,
                "scan_id": meta.scan_id,
                "timestamp": meta.timestamp,
                "duration_ms": meta.duration_ms,
                "files_scanned": meta.files_scanned,
                "rules_checked": meta.rules_checked,
            },
            "summary": {
                "total_findings": collection.total,
                "severity_counts": sev_summary,
            },
            "findings": findings_payload,
            "rag_context": [dict(ctx) for ctx in result.rag_context],
            "errors": list(result.errors),
        }

        content = json.dumps(report_dict, indent=2)
        target.write(content)
        target.close()
