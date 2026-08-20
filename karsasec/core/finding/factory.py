"""FindingFactory module for computing fingerprints and instantiating immutable Finding models."""

import hashlib
import uuid
from pathlib import Path
from typing import Any

from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.matcher.result import RuleMatch
from karsasec.rules.schema import Rule


class FindingFactory:
    """Computes deterministic SHA-256 fingerprints and builds immutable Finding instances."""

    def compute_fingerprint(self, rule_id: str, file_path: Path, line: int, snippet: str) -> str:
        """Computes a deterministic SHA-256 fingerprint for finding deduplication."""
        norm_path = str(file_path).replace("\\", "/")
        snippet_hash = hashlib.sha256(snippet.encode("utf-8", errors="ignore")).hexdigest()[:16]
        raw_key = f"{norm_path}:{rule_id}:{line}:{snippet_hash}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:32]

    def create_finding(
        self,
        rule: Rule,
        file_path: Path,
        evidence: Evidence,
        match_result: RuleMatch,
        metadata: dict[str, Any] | None = None,
        source_text: str = "",
    ) -> Finding:
        """Assembles a CandidateFinding and passes it through SemanticFindingQualifier."""
        from karsasec.core.finding.candidate import CandidateFinding
        from karsasec.core.finding.qualifier import SemanticFindingQualifier

        candidate_id = f"cand-{uuid.uuid4().hex[:8]}"
        matched_text = (
            match_result.matched_text
            if hasattr(match_result, "matched_text") and match_result.matched_text
            else evidence.snippet
        )

        ast_node = ASTNode(node_id=match_result.node_id, node_type="sink", start=None, end=None)

        candidate = CandidateFinding(
            candidate_id=candidate_id,
            rule=rule,
            rule_id=rule.id,
            file_path=file_path,
            line=evidence.line,
            column=evidence.column,
            matched_text=matched_text,
            snippet=evidence.snippet,
            source_text=source_text,
            ast_node=ast_node,
            language=getattr(rule.match, "language", "PHP") or "PHP",
            metadata=metadata or {},
        )

        qualifier = SemanticFindingQualifier()
        return qualifier.qualify_candidate(candidate)


# Global default factory instance
finding_factory = FindingFactory()
