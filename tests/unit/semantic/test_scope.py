"""Unit tests for semantic scope hierarchy and bindings."""

from karsasec.semantic.scope import Scope, ScopeType


def test_scope_creation_and_type():
    scope = Scope(ScopeType.GLOBAL)
    assert scope.scope_type == ScopeType.GLOBAL
    assert scope.parent is None
    assert len(scope.bindings) == 0

def test_scope_define_and_local_lookup():
    scope = Scope(ScopeType.FUNCTION)
    scope.define("my_var", "my_module.my_var")
    assert scope.lookup("my_var") == "my_module.my_var"
    assert scope.lookup("non_existent") is None

def test_scope_parent_hierarchy_lookup():
    parent_scope = Scope(ScopeType.GLOBAL)
    parent_scope.define("global_var", "global_val")
    parent_scope.define("shadow_var", "parent_val")

    child_scope = Scope(ScopeType.FUNCTION, parent=parent_scope)
    child_scope.define("local_var", "local_val")
    child_scope.define("shadow_var", "local_val")

    # Local variable
    assert child_scope.lookup("local_var") == "local_val"
    # Global variable (inherited)
    assert child_scope.lookup("global_var") == "global_val"
    # Shadowed variable (local overrides parent)
    assert child_scope.lookup("shadow_var") == "local_val"
    # Parent scope still has its own shadow_var value
    assert parent_scope.lookup("shadow_var") == "parent_val"
