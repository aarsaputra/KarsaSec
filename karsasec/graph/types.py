"""Type definitions and data models for KarsaSec Call Graph."""

from enum import Enum
from pathlib import Path


class CallType(Enum):
    STATIC = "static"      # Direct function or class method call
    DYNAMIC = "dynamic"    # Method call resolved dynamically
    INDIRECT = "indirect"  # Callback or function pointer execution

class CallNode:
    """Represents a function, method, or global entry point in the Call Graph."""

    __slots__ = (
        "node_id",
        "name",
        "qualified_name",
        "file_path",
        "parameters",
        "is_async",
        "class_owner",
        "language",
    )

    def __init__(
        self,
        node_id: str,
        name: str,
        qualified_name: str,
        file_path: Path,
        parameters: list[str],
        is_async: bool = False,
        class_owner: str | None = None,
        language: str = "Generic",
    ) -> None:
        self.node_id = node_id
        self.name = name
        self.qualified_name = qualified_name
        self.file_path = file_path
        self.parameters = parameters
        self.is_async = is_async
        self.class_owner = class_owner
        self.language = language

    def __repr__(self) -> str:
        return (
            f"CallNode(name={self.name}, qname={self.qualified_name}, "
            f"file={self.file_path.name}, lang={self.language})"
        )

class CallEdge:
    """Represents an execution control flow transition from caller to callee."""

    __slots__ = (
        "caller_id",
        "callee_id",
        "call_site_id",
        "call_type",
        "resolved_symbol",
        "line",
        "column",
    )

    def __init__(
        self,
        caller_id: str,
        callee_id: str,
        call_site_id: str,
        call_type: CallType,
        resolved_symbol: str | None = None,
        line: int = 1,
        column: int = 1,
    ) -> None:
        self.caller_id = caller_id
        self.callee_id = callee_id
        self.call_site_id = call_site_id
        self.call_type = call_type
        self.resolved_symbol = resolved_symbol
        self.line = line
        self.column = column

    def __repr__(self) -> str:
        return (
            f"CallEdge(caller={self.caller_id[:8]} -> callee={self.callee_id[:8]} "
            f"type={self.call_type.value} symbol={self.resolved_symbol})"
        )
