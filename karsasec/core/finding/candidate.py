"""CandidateFinding model: raw rule engine matches before semantic qualification (E12-3)."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.schema import Rule


@dataclass(frozen=True)
class CandidateFinding:
    """Raw finding candidate produced by AST/Rule Matcher before semantic qualification.

    A CandidateFinding retains full AST context, source text, and rule metadata,
    allowing the SemanticFindingQualifier to perform deep verification without dropping evidence.
    """
    candidate_id: str
    rule: Rule
    rule_id: str
    file_path: Path
    line: int
    column: int
    matched_text: str
    snippet: str
    source_text: str
    ast_node: ASTNode | None = None
    language: str = "PHP"
    metadata: dict[str, Any] = field(default_factory=dict)
