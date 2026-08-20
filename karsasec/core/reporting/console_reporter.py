"""ConsoleReporter producing clean terminal security reports for developers."""

from karsasec.core.execution.result import ExecutionResult
from karsasec.core.finding.collection import FindingCollection
from karsasec.core.reporting.formatter import SeverityFormatter
from karsasec.core.reporting.reporter import Reporter
from karsasec.core.reporting.target import ReportTarget


class ConsoleReporter(Reporter):
    """Generates human-readable terminal reports for developer CLI output."""

    def __init__(self, no_color: bool = False) -> None:
        self.formatter = SeverityFormatter(no_color=no_color)

    def generate(self, result: ExecutionResult, target: ReportTarget) -> None:
        collection = FindingCollection(result.findings).sort_by_severity(descending=True)

        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("              KARSASEC SECURITY SCAN REPORT              ")
        lines.append("=" * 60)
        lines.append(f"Scan ID        : {result.scan_id}")
        lines.append(f"Files Scanned  : {result.files_scanned}")
        lines.append(f"Rules Evaluated: {result.rules_checked}")
        lines.append(f"Duration       : {result.execution_time_ms:.2f} ms")
        lines.append(f"Total Findings : {collection.total}")
        lines.append("-" * 60)

        if collection.total == 0:
            lines.append("✓ No security vulnerabilities detected.")
        else:
            lines.append("\n[FINDINGS DETECTED]\n")
            for idx, finding in enumerate(collection.findings, start=1):
                sev_label = self.formatter.format_severity(finding.severity)
                norm_path = str(finding.file_path).replace("\\", "/")
                lines.append(f"{idx}. {sev_label} {finding.title} ({finding.rule_id})")
                lines.append(f"   Location : {norm_path}:{finding.evidence.line}:{finding.evidence.column}")
                lines.append(f"   CWE/OWASP: {finding.cwe_id} | {finding.owasp}")
                lines.append(f"   Snippet  : {finding.evidence.snippet.strip()}")
                lines.append(f"   Fix      : {finding.remediation}")
                lines.append("")

        lines.append("-" * 60)
        lines.append("SEVERITY SUMMARY:")
        for sev, count in collection.severity_summary.items():
            if count > 0:
                sev_str = self.formatter.format_severity(sev)
                lines.append(f"  {sev_str:<25} : {count}")

        if result.rag_context:
            lines.append("-" * 60)
            lines.append("RAG CONTEXT RETRIEVAL:")
            for idx, context in enumerate(result.rag_context, start=1):
                lines.append(f"{idx}. {context.get('document_id')} (score={context.get('score'):.4f})")
                lines.append(f"   Source: {context.get('source_path')}")
                text_snippet = str(context.get("text", "")).strip().replace("\n", " ")
                lines.append(f"   Snippet: {text_snippet[:200]}")
                lines.append("")

        lines.append("=" * 60 + "\n")

        content = "\n".join(lines)
        target.write(content)
        target.close()
