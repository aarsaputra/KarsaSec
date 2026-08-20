"""Unit tests for transitive alias resolution and tracking."""

from karsasec.semantic.alias_tracker import AliasTracker


def test_alias_tracker_flat():
    tracker = AliasTracker()
    tracker.register_alias("runner", "os.system")
    assert tracker.resolve("runner") == "os.system"
    assert tracker.resolve("other") == "other"


def test_alias_tracker_transitive():
    tracker = AliasTracker()
    tracker.register_alias("a", "b")
    tracker.register_alias("b", "c")
    tracker.register_alias("c", "os.system")
    assert tracker.resolve("a") == "os.system"
    assert tracker.resolve("b") == "os.system"
    assert tracker.resolve("c") == "os.system"


def test_alias_tracker_cyclic_safety():
    tracker = AliasTracker()
    tracker.register_alias("a", "b")
    tracker.register_alias("b", "a")  # Cycle
    # Should resolve gracefully without infinite recursion
    assert tracker.resolve("a") == "a" or tracker.resolve("a") == "b"
