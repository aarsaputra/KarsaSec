"""Semantic analysis module for KarsaSec."""

from karsasec.semantic.scope import Scope, ScopeType
from karsasec.semantic.namespace import NamespaceResolver
from karsasec.semantic.alias_tracker import AliasTracker
from karsasec.semantic.symbol_table import SemanticSymbol
from karsasec.semantic.resolver import SemanticResolver, SemanticGraph

__all__ = [
    "Scope",
    "ScopeType",
    "NamespaceResolver",
    "AliasTracker",
    "SemanticSymbol",
    "SemanticResolver",
    "SemanticGraph",
]
