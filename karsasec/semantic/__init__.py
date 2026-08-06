"""Semantic analysis module for KarsaSec."""

from karsasec.semantic.alias_tracker import AliasTracker
from karsasec.semantic.namespace import NamespaceResolver
from karsasec.semantic.resolver import SemanticGraph, SemanticResolver
from karsasec.semantic.scope import Scope, ScopeType
from karsasec.semantic.symbol_table import SemanticSymbol

__all__ = [
    "Scope",
    "ScopeType",
    "NamespaceResolver",
    "AliasTracker",
    "SemanticSymbol",
    "SemanticResolver",
    "SemanticGraph",
]
