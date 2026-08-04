"""EvidenceCollector module for extracting code evidence and context lines from source code."""

from typing import Optional, Tuple
from karsasec.core.execution.errors import EvidenceUnavailableError
from karsasec.core.finding.evidence import Evidence
from karsasec.parser.ast_nodes import ASTNode

class EvidenceCollector:
    """Extracts vulnerable code snippets and context lines from raw source bytes."""

    def extract_evidence(
        self,
        node: ASTNode,
        source_bytes: Optional[bytes],
        context_window: int = 2,
    ) -> Evidence:
        """Extracts Evidence from source bytes for a given ASTNode.

        Raises:
            EvidenceUnavailableError: If source_bytes is None.
        """
        if source_bytes is None:
            raise EvidenceUnavailableError("Mandatory source_bytes parameter is missing.")

        line = node.start.line if node.start and node.start.line > 0 else 1
        column = node.start.column if node.start else 0

        # Decode snippet
        snippet = node.get_text(source_bytes)
        if not snippet:
            snippet = f"/* AST node {node.node_type} at line {line} */"

        # Decode context lines
        text_lines = source_bytes.decode("utf-8", errors="ignore").splitlines()
        start_idx = max(0, line - 1 - context_window)
        end_idx = min(len(text_lines), line + context_window)
        context_lines: Tuple[str, ...] = tuple(text_lines[start_idx:end_idx])

        return Evidence(
            snippet=snippet,
            line=line,
            column=column,
            context_lines=context_lines,
        )

# Global default collector instance
evidence_collector = EvidenceCollector()
