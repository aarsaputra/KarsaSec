"""Multi-Layered IR architecture defining High-Level IR (HIR), Medium-Level IR (MIR), and Analysis-Level IR (LIR)."""

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# 1. High-Level IR (HIR) - Preserves language-specific syntactic constructs
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class HIRNode:
    node_id: str
    language: str
    syntax_kind: str


# ---------------------------------------------------------------------------
# 2. Medium-Level IR (MIR) - Unified Semantic Program Model
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class MIRNode:
    node_id: str


@dataclass(frozen=True)
class MIRConditional(MIRNode):
    condition_var: str
    then_branch: list[MIRNode] = field(default_factory=list)
    else_branch: list[MIRNode] = field(default_factory=list)


@dataclass(frozen=True)
class MIRCall(MIRNode):
    callee: str
    arguments: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 3. Low-Level Analysis IR (LIR) - Taint & Flow Analysis Primitives
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class LIRNode:
    node_id: str


@dataclass(frozen=True)
class LIRSource(LIRNode):
    source_type: str  # e.g., "HTTP_PARAM", "USER_INPUT"
    var_name: str


@dataclass(frozen=True)
class LIRSink(LIRNode):
    sink_type: str  # e.g., "SQL_QUERY", "EXEC_CMD"
    target_callee: str


@dataclass(frozen=True)
class LIRSanitizer(LIRNode):
    sanitizer_type: str  # e.g., "HTML_ESCAPE", "INT_CAST"
    var_name: str
