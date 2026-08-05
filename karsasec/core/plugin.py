"""Base abstract plugin definitions and contract DTOs."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple
from karsasec.core.context import AnalysisContext

if TYPE_CHECKING:
    from karsasec.parser.ast_nodes import FileNode

@dataclass
class Diagnostic:
    """Structured diagnostic warning or error generated during parsing or analysis."""
    code: str
    severity: str  # ERROR, WARNING, INFO
    message: str
    file_path: Optional[Path] = None
    line: int = 0
    column: int = 0

@dataclass
class SymbolTable:
    """Fast symbol table storing extracted high-level symbols for Rule Engine lookup (Sprint 3)."""
    functions: List[str] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    globals: List[str] = field(default_factory=list)

from karsasec.rules.enums import AnalysisCapability

@dataclass(frozen=True)
class ParseResult:
    """Contract returned by ParserPlugin parsing operations containing AST, diagnostics, and metrics (Immutable)."""
    language: str
    file_path: Path
    root: Optional["FileNode"] = None
    symbol_table: SymbolTable = field(default_factory=SymbolTable)
    diagnostics: Tuple[Diagnostic, ...] = field(default_factory=tuple)
    parse_time_ms: float = 0.0
    parser_version: str = "0.1.0"
    engine: str = "Tree-sitter v0.25"
    target_kind: str = "SOURCE_CODE"
    target_format: str = "Python"
    capabilities: Tuple[AnalysisCapability, ...] = field(
        default_factory=lambda: (
            AnalysisCapability.AST,
            AnalysisCapability.POSITION,
            AnalysisCapability.COMMENTS,
            AnalysisCapability.HIERARCHY,
        )
    )

ParsedDocument = ParseResult

class BasePlugin(ABC):
    """Abstract base class for all KarsaSec plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the plugin."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Version string of the plugin."""
        pass

class ParserPlugin(BasePlugin, ABC):
    """Abstract base class for AST Language Parsers."""

    @property
    @abstractmethod
    def supported_language(self) -> str:
        """Primary programming language name supported by this parser plugin."""
        pass

    @abstractmethod
    def can_parse(self, file_extension: str) -> bool:
        """Checks if plugin supports parsing the file extension."""
        pass

    @abstractmethod
    def parse_file(self, file_path: Path) -> ParseResult:
        """Parses source file and extracts AST nodes and SymbolTable."""
        pass

class ScannerPlugin(BasePlugin, ABC):
    """Abstract base class for Security Rule Scanners."""

    @abstractmethod
    def execute_scan(self, context: AnalysisContext) -> List[Dict[str, Any]]:
        """Executes security checks against analysis context."""
        pass
