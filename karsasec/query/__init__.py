"""KarsaSec Query Engine & Predicate DSL.

Provides a fluent Python query DSL for expressing complex code patterns and security predicates
independently of YAML configuration schemas.
"""

from karsasec.query.dsl import Predicate, Query

__all__ = [
    "Query",
    "Predicate",
]
