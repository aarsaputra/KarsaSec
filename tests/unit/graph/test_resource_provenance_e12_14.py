"""Adversarial Unit Test Suite for Sprint E12-14 Call-Context & Resource Provenance Engine.

Coverage (16 Mandatory Scenarios):
  01: Cross-file constant resolution
  02: Tainted cross-file constant rejection
  03: Guard lifetime isolation across un-related files
  04: Interprocedural guard reassignment kill
  05: md5 non-security cache context
  06: md5 security-sensitive password context
  07: Cyclic include graph safety
  08: Ambiguous definition resolution
  09: Multi-level nested constant concatenation
  10: Static vs tainted include discrimination
  11: Conditional constant definition handling
  12: Definition-after-use evaluation order sensitivity
  13: Identical multi-definition resolution
  14: Conflicting multi-definition resolution
  15: Unknown crypto context fallback (retain finding)
  16: Interprocedural version mismatch handling
"""

from __future__ import annotations


from karsasec.graph.constant_resolver import ConstantResolution
from karsasec.graph.dataflow.abstract_state import AbstractEnvironment, SemanticConstraint
from karsasec.graph.dataflow.crypto_context import CryptoContextAnalyzer, CryptoContextKind
from karsasec.graph.dataflow.interprocedural_guard import (
    GuardFact,
    InterproceduralGuardManager,
)
from karsasec.graph.resource_graph import (
    ResourceEdge,
    ResourceEdgeKind,
    ResourceGraph,
    ResourceKind,
    ResourceNode,
)
from karsasec.graph.symbol_resolver import SymbolResolver


def test_01_cross_file_constant() -> None:
    rg = ResourceGraph()
    resolver = SymbolResolver(rg)
    files = {
        "config.php": "<?php define('ROOT', '/var/www');",
        "index.php": "<?php require_once ROOT . '/lib.php';",
    }
    ev = resolver.resolve_expression("ROOT . '/lib.php'", files, requesting_file="index.php")
    assert ev.resolution == ConstantResolution.DERIVED_STATIC
    assert ev.resolved_value == "/var/www/lib.php"


def test_02_tainted_constant() -> None:
    rg = ResourceGraph()
    resolver = SymbolResolver(rg)
    files = {
        "config.php": "<?php define('P', $_GET['p']);",
        "index.php": "<?php require_once P;",
    }
    ev = resolver.resolve_constant("P", files, requesting_file="index.php")
    assert ev.resolution == ConstantResolution.TAINTED


def test_03_guard_lifetime_isolation() -> None:
    rg = ResourceGraph()
    # fileA and fileB have NO include/call relationship in rg
    rg.add_node(ResourceNode("fileA.php", ResourceKind.FILE))
    rg.add_node(ResourceNode("fileB.php", ResourceKind.FILE))

    manager = InterproceduralGuardManager(rg)
    fact = GuardFact(
        var_name="$id",
        var_version="$id#1",
        constraint=SemanticConstraint.NUMERIC,
        source_file="fileA.php",
    )
    manager.register_fact(fact)

    env_b = AbstractEnvironment()
    env_b.set_value(env_b.assignment_kill("$id"))

    # Should NOT propagate because fileA.php and fileB.php are not connected in ResourceGraph
    facts = manager.get_propagated_facts("fileB.php", "$id", env_b)
    assert SemanticConstraint.NUMERIC not in facts


def test_04_guard_reassignment_kill() -> None:
    rg = ResourceGraph()
    rg.add_node(ResourceNode("fileA.php", ResourceKind.FILE))
    rg.add_node(ResourceNode("fileB.php", ResourceKind.FILE))
    rg.add_edge(ResourceEdge("fileA.php", "fileB.php", ResourceEdgeKind.INCLUDES))

    manager = InterproceduralGuardManager(rg)
    fact = GuardFact(
        var_name="$id",
        var_version="$id#1",
        constraint=SemanticConstraint.NUMERIC,
        source_file="fileA.php",
    )
    manager.register_fact(fact)

    env_b = AbstractEnvironment()
    v1 = env_b.assignment_kill("$id")  # creates $id#1
    v2 = env_b.assignment_kill("$id")  # reassignment creates $id#2

    # Since env_b current version is $id#2, fact for $id#1 is invalidated
    facts = manager.get_propagated_facts("fileB.php", "$id", env_b)
    assert SemanticConstraint.NUMERIC not in facts


def test_05_md5_cache_context() -> None:
    analyzer = CryptoContextAnalyzer()
    stmts = ["$cache_key = md5($cache_id);", "$table[$cache_key] = $data;"]
    ev = analyzer.analyze_hash_usage("md5", "$cache_id", "$cache_key", stmts)
    assert ev.context_kind in (CryptoContextKind.NON_SECURITY_IDENTIFIER, CryptoContextKind.CACHE_KEY)
    assert ev.context_kind != CryptoContextKind.PASSWORD_HASH


def test_06_md5_password_context() -> None:
    analyzer = CryptoContextAnalyzer()
    stmts = ["$pwd_hash = md5($_POST['password']);", "if ($pwd_hash == $db_pass) exit;"]
    ev = analyzer.analyze_hash_usage("md5", "$_POST['password']", "$pwd_hash", stmts)
    assert ev.context_kind == CryptoContextKind.PASSWORD_HASH


def test_07_cyclic_include() -> None:
    rg = ResourceGraph()
    rg.add_node(ResourceNode("a.php", ResourceKind.FILE))
    rg.add_node(ResourceNode("b.php", ResourceKind.FILE))
    rg.add_edge(ResourceEdge("a.php", "b.php", ResourceEdgeKind.INCLUDES))
    rg.add_edge(ResourceEdge("b.php", "a.php", ResourceEdgeKind.INCLUDES))

    chain = rg.find_include_chain("a.php", "target.php")
    assert chain is None


def test_08_ambiguous_definition() -> None:
    resolver = SymbolResolver()
    files = {
        "a.php": "<?php define('HOST', 'alpha');",
        "b.php": "<?php define('HOST', 'beta');",
    }
    ev = resolver.resolve_constant("HOST", files)
    assert ev.resolution == ConstantResolution.UNKNOWN


def test_09_nested_constant_concatenation() -> None:
    resolver = SymbolResolver()
    files = {
        "a.php": "<?php define('BASE', '/var/app');",
        "b.php": "<?php define('SUB', BASE . '/modules');",
    }
    ev = resolver.resolve_constant("SUB", files)
    assert ev.resolution in (ConstantResolution.DERIVED_STATIC, ConstantResolution.STATIC_CONSTANT)
    assert ev.resolved_value == "/var/app/modules"


def test_10_static_vs_tainted_include() -> None:
    resolver = SymbolResolver()
    files = {
        "config.php": "<?php define('DVWA_WEB_PAGE_TO_ROOT', '../../');",
    }
    ev_static = resolver.resolve_expression("DVWA_WEB_PAGE_TO_ROOT . 'vulnerabilities/fi/source/file1.php'", files)
    assert ev_static.resolution == ConstantResolution.DERIVED_STATIC

    ev_tainted = resolver.resolve_expression("$_GET['page']", files)
    assert ev_tainted.resolution not in (ConstantResolution.DERIVED_STATIC, ConstantResolution.STATIC_CONSTANT, ConstantResolution.STATIC_LITERAL)


def test_11_conditional_constant_definition() -> None:
    resolver = SymbolResolver()
    files = {
        "a.php": "<?php if ($cond) { define('COND_CONST', '/path'); }",
    }
    ev = resolver.resolve_constant("COND_CONST", files)
    assert ev.resolution == ConstantResolution.UNKNOWN


def test_12_definition_after_use() -> None:
    resolver = SymbolResolver()
    files = {
        "a.php": """<?php
        $x = DEF_LATER;
        define('DEF_LATER', '/path');
        """,
    }
    ev = resolver.resolve_constant("DEF_LATER", files, requesting_file="a.php", requesting_line=2)
    assert ev.resolution == ConstantResolution.UNKNOWN


def test_13_identical_multi_definition() -> None:
    resolver = SymbolResolver()
    files = {
        "a.php": "<?php define('VER', '1.0');",
        "b.php": "<?php define('VER', '1.0');",
    }
    ev = resolver.resolve_constant("VER", files)
    assert ev.resolution == ConstantResolution.STATIC_CONSTANT
    assert ev.resolved_value == "1.0"


def test_14_conflicting_multi_definition() -> None:
    resolver = SymbolResolver()
    files = {
        "a.php": "<?php define('ENV', 'dev');",
        "b.php": "<?php define('ENV', 'prod');",
    }
    ev = resolver.resolve_constant("ENV", files)
    assert ev.resolution == ConstantResolution.UNKNOWN


def test_15_unknown_crypto_context() -> None:
    analyzer = CryptoContextAnalyzer()
    stmts = ["$x = md5($input);"]
    ev = analyzer.analyze_hash_usage("md5", "$input", "$x", stmts)
    assert ev.context_kind == CryptoContextKind.UNKNOWN


def test_16_interprocedural_version_mismatch() -> None:
    rg = ResourceGraph()
    rg.add_node(ResourceNode("fileA.php", ResourceKind.FILE))
    rg.add_node(ResourceNode("fileB.php", ResourceKind.FILE))
    rg.add_edge(ResourceEdge("fileA.php", "fileB.php", ResourceEdgeKind.INCLUDES))

    manager = InterproceduralGuardManager(rg)
    fact = GuardFact(
        var_name="$x",
        var_version="$x#1",
        constraint=SemanticConstraint.NUMERIC,
        source_file="fileA.php",
    )
    manager.register_fact(fact)

    env_b = AbstractEnvironment()
    v1 = env_b.assignment_kill("$x")
    v2 = env_b.assignment_kill("$x")  # now version $x#2

    facts = manager.get_propagated_facts("fileB.php", "$x", env_b)
    assert SemanticConstraint.NUMERIC not in facts
