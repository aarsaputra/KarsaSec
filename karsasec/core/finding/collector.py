"""EvidenceCollector extracting source snippet and context window lines from ASTNode and source_bytes."""

from typing import Optional, Tuple
from karsasec.core.finding.errors import EvidenceUnavailableError
from karsasec.core.finding.evidence import Evidence
from karsasec.parser.ast_nodes import ASTNode

class EvidenceCollector:
    """Decoupled evidence collector extracting line, column, snippet, and context lines."""

    def extract_evidence(
        self,
        node: ASTNode,
        source_bytes: Optional[bytes],
        context_window: int = 10,
    ) -> Evidence:
        """Extracts Evidence DTO from an ASTNode and source bytes.

        Raises:
            EvidenceUnavailableError: If source_bytes is None or node byte offsets are invalid.
        """
        if source_bytes is None:
            raise EvidenceUnavailableError("source_bytes is required for evidence collection")

        if node.byte_start < 0 or node.byte_end > len(source_bytes) or node.byte_start > node.byte_end:
            raise EvidenceUnavailableError(
                f"Invalid node byte range [{node.byte_start}:{node.byte_end}] for source length {len(source_bytes)}"
            )

        snippet_raw = source_bytes[node.byte_start:node.byte_end]
        snippet = snippet_raw.decode("utf-8", errors="ignore").strip()

        source_text = source_bytes.decode("utf-8", errors="ignore")
        lines = source_text.splitlines()

        line_num = node.start.line if node.start else 1
        col_num = node.start.column if node.start else 0

        # Calculate context lines
        start_idx = max(0, line_num - 1 - context_window)
        end_idx = min(len(lines), line_num + context_window)
        context_lines: Tuple[str, ...] = tuple(lines[start_idx:end_idx])

        return Evidence(
            snippet=snippet if snippet else node.node_type,
            line=line_num,
            column=col_num,
            context_lines=context_lines,
        )

# Global default instance
evidence_collector = EvidenceCollector()
