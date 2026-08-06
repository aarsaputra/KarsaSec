"""KarsaSec Parser Package."""

from karsasec.parser.ast import (
    ASTVisitor,
    ASTWalker,
    StopTraversal,
    TraversalStrategy,
    VisitorContext,
)
from karsasec.parser.ast_nodes import (
    AssignmentNode,
    ASTNode,
    CallNode,
    ClassNode,
    FileNode,
    FunctionNode,
    ImportNode,
    Position,
)
from karsasec.parser.detector import ProjectDetector, detect_project
from karsasec.parser.framework import FrameworkDetector
from karsasec.parser.language import LanguageDetector
from karsasec.parser.profile import ProjectProfiler
from karsasec.parser.python_parser import PythonParserPlugin, python_parser_plugin
from karsasec.parser.registry import ParserRegistry, parser_registry
from karsasec.parser.tree_sitter import TreeSitterEngine, ts_engine

__all__ = [
    "ASTNode",
    "FileNode",
    "FunctionNode",
    "ClassNode",
    "ImportNode",
    "CallNode",
    "AssignmentNode",
    "Position",
    "ProjectDetector",
    "detect_project",
    "LanguageDetector",
    "FrameworkDetector",
    "ProjectProfiler",
    "ParserRegistry",
    "parser_registry",
    "PythonParserPlugin",
    "python_parser_plugin",
    "TreeSitterEngine",
    "ts_engine",
    "ASTVisitor",
    "ASTWalker",
    "VisitorContext",
    "TraversalStrategy",
    "StopTraversal",
]
