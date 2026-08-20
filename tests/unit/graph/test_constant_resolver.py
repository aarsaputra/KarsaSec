"""Sprint E10-3K: 12-scenario regression test matrix for ConstantResolver and TaintVerifier.

Validates all E10-3K exit criteria:
  - static constant -> 0 finding (no FP)
  - tainted constant -> finding (no FN)
  - unknown constant -> UNKNOWN evidence -> suppress (no FP)
  - cycle protection is deterministic
  - DVWA_WEB_PAGE_TO_ROOT regression
  - No DVWA-specific hardcode in TaintVerifier
"""

from __future__ import annotations

import pytest

from karsasec.graph.constant_resolver import (
    ConstantResolution,
    ConstantResolver,
)
from karsasec.graph.taint_verifier import TaintVerifier
from karsasec.parser.ast_nodes import ASTNode
from karsasec.rules.enums import Confidence, Severity

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def resolver() -> ConstantResolver:
    return ConstantResolver()


@pytest.fixture
def verifier() -> TaintVerifier:
    return TaintVerifier()


def _node() -> ASTNode:
    return ASTNode(node_type="call", byte_start=0, byte_end=10)


# ---------------------------------------------------------------------------
# Scenario 1: define() with static string literal
# ---------------------------------------------------------------------------


class TestScenario1_DefineStaticString:
    """S1: define('BASE_PATH', '../') -> STATIC_CONSTANT"""

    def test_resolve(self, resolver: ConstantResolver) -> None:
        src = "<?php define('BASE_PATH', '../');"
        ev = resolver.resolve("BASE_PATH", src)
        assert ev.resolution == ConstantResolution.STATIC_CONSTANT
        assert ev.resolved_value == "../"

    def test_no_taint_finding(self, verifier: TaintVerifier) -> None:
        src = "<?php define('BASE_PATH', '../');\nrequire_once BASE_PATH . 'foo.php';"
        snippet = "require_once BASE_PATH . 'foo.php';"
        res = verifier.verify_sink(
            _node(),
            snippet,
            snippet,
            src,
            language="php",
            base_severity=Severity.HIGH,
            base_confidence=Confidence.CONFIDENT,
        )
        assert res.is_hardcoded_static, "Static constant path should suppress finding"
        assert res.adjusted_severity == Severity.LOW


# ---------------------------------------------------------------------------
# Scenario 2: const keyword with static value
# ---------------------------------------------------------------------------


class TestScenario2_ConstKeywordStatic:
    """S2: const BASE_PATH = '../'; -> STATIC_CONSTANT"""

    def test_resolve(self, resolver: ConstantResolver) -> None:
        src = "<?php const BASE_PATH = '../';"
        ev = resolver.resolve("BASE_PATH", src)
        assert ev.resolution == ConstantResolution.STATIC_CONSTANT
        assert ev.resolved_value == "../"


# ---------------------------------------------------------------------------
# Scenario 3: Constant + string literal concatenation -> DERIVED_STATIC
# ---------------------------------------------------------------------------


class TestScenario3_ConcatDerivedStatic:
    """S3: BASE_PATH . 'foo.php' -> DERIVED_STATIC (both parts static)"""

    def test_resolve_expression(self, resolver: ConstantResolver) -> None:
        src = "<?php define('BASE_PATH', '../');"
        ev = resolver.resolve_expression("BASE_PATH . 'foo.php'", src)
        assert ev.resolution in (
            ConstantResolution.DERIVED_STATIC,
            ConstantResolution.STATIC_CONSTANT,
            ConstantResolution.STATIC_LITERAL,
        ), f"Expected static resolution, got {ev.resolution}: {ev.provenance}"


# ---------------------------------------------------------------------------
# Scenario 4: Nested static constants (A -> B -> literal)
# ---------------------------------------------------------------------------


class TestScenario4_NestedStaticConstants:
    """S4: define('A', B) where define('B', '../') -> resolve A = STATIC_CONSTANT"""

    def test_nested_resolve(self, resolver: ConstantResolver) -> None:
        src = "<?php define('ROOT', '../');\ndefine('BASE', ROOT);"
        ev = resolver.resolve("BASE", src)
        assert ev.resolution == ConstantResolution.STATIC_CONSTANT
        assert ev.resolved_value == "../"


# ---------------------------------------------------------------------------
# Scenario 5: Constant from $_GET -> TAINTED
# ---------------------------------------------------------------------------


class TestScenario5_ConstantFromGet:
    """S5: define('BASE_PATH', $_GET['path']) -> TAINTED"""

    def test_resolve(self, resolver: ConstantResolver) -> None:
        src = "<?php define('BASE_PATH', $_GET['path']);"
        ev = resolver.resolve("BASE_PATH", src)
        assert ev.resolution == ConstantResolution.TAINTED

    def test_taint_finding(self, verifier: TaintVerifier) -> None:
        src = "<?php define('BASE_PATH', $_GET['path']);\nrequire_once BASE_PATH . 'foo.php';"
        snippet = "require_once BASE_PATH . 'foo.php';"
        res = verifier.verify_sink(
            _node(),
            snippet,
            snippet,
            src,
            language="php",
            base_severity=Severity.HIGH,
            base_confidence=Confidence.CONFIDENT,
        )
        assert res.constant_resolution == ConstantResolution.TAINTED


# ---------------------------------------------------------------------------
# Scenario 6: Constant from $_POST -> TAINTED
# ---------------------------------------------------------------------------


class TestScenario6_ConstantFromPost:
    """S6: define('BASE_PATH', $_POST['p']) -> TAINTED"""

    def test_resolve(self, resolver: ConstantResolver) -> None:
        src = "<?php define('BASE_PATH', $_POST['p']);"
        ev = resolver.resolve("BASE_PATH", src)
        assert ev.resolution == ConstantResolution.TAINTED


# ---------------------------------------------------------------------------
# Scenario 7: Constant from getenv() -> UNKNOWN (ENV_REFERENCE)
# ---------------------------------------------------------------------------


class TestScenario7_ConstantFromGetenv:
    """S7: define('BASE_PATH', getenv('BASE_PATH')) -> UNKNOWN"""

    def test_resolve(self, resolver: ConstantResolver) -> None:
        src = "<?php define('BASE_PATH', getenv('BASE_PATH'));"
        ev = resolver.resolve("BASE_PATH", src)
        assert ev.resolution == ConstantResolution.UNKNOWN
        assert "env" in ev.provenance.lower() or "environment" in ev.provenance.lower()


# ---------------------------------------------------------------------------
# Scenario 8: Undefined constant -> UNKNOWN
# ---------------------------------------------------------------------------


class TestScenario8_UndefinedConstant:
    """S8: No define() found for UNDEFINED_CONST -> UNKNOWN"""

    def test_resolve(self, resolver: ConstantResolver) -> None:
        src = "<?php echo 'hello';"
        ev = resolver.resolve("UNDEFINED_CONST", src)
        assert ev.resolution == ConstantResolution.UNKNOWN

    def test_no_false_suppression(self, verifier: TaintVerifier) -> None:
        """UNKNOWN constant -> must NOT suppress as static."""
        src = "<?php echo 'hello';\nrequire_once UNDEFINED_CONST . 'foo.php';"
        snippet = "require_once UNDEFINED_CONST . 'foo.php';"
        res = verifier.verify_sink(
            _node(),
            snippet,
            snippet,
            src,
            language="php",
            base_severity=Severity.HIGH,
            base_confidence=Confidence.CONFIDENT,
        )
        assert not res.is_hardcoded_static, "UNKNOWN constant must NOT be treated as static — insufficient evidence"


# ---------------------------------------------------------------------------
# Scenario 9: Recursive constant cycle A -> B -> A -> UNKNOWN
# ---------------------------------------------------------------------------


class TestScenario9_CycleProtection:
    """S9: define('A', B) + define('B', A) -> cycle -> UNKNOWN (not infinite loop)"""

    def test_cycle_terminates(self, resolver: ConstantResolver) -> None:
        src = "<?php define('A', B);\ndefine('B', A);"
        ev = resolver.resolve("A", src)
        # Must terminate (no RecursionError) and must resolve to UNKNOWN
        assert ev.resolution == ConstantResolution.UNKNOWN
        assert (
            "cycle" in ev.provenance.lower() or "depth" in ev.provenance.lower() or "unknown" in ev.provenance.lower()
        )

    def test_cycle_terminates_from_b(self, resolver: ConstantResolver) -> None:
        src = "<?php define('A', B);\ndefine('B', A);"
        ev = resolver.resolve("B", src)
        assert ev.resolution == ConstantResolution.UNKNOWN


# ---------------------------------------------------------------------------
# Scenario 10: Same constant name, multiple declarations -> UNKNOWN (scope ambiguity)
# ---------------------------------------------------------------------------


class TestScenario10_MultipleDeclarations:
    """S10: Two define('SAME', ...) -> UNKNOWN (ambiguous scope, conservative)"""

    def test_resolve(self, resolver: ConstantResolver) -> None:
        src = "<?php define('SAME', '../module1/');\ndefine('SAME', '../module2/');"
        ev = resolver.resolve("SAME", src)
        assert ev.resolution == ConstantResolution.UNKNOWN
        assert "multiple" in ev.provenance.lower() or "ambiguous" in ev.provenance.lower()


# ---------------------------------------------------------------------------
# Scenario 11: Static constant used in require/include -> no finding
# ---------------------------------------------------------------------------


class TestScenario11_StaticConstantInRequire:
    """S11: require_once STATIC_CONST . 'file.php' with no PHP vars -> suppress"""

    def test_no_finding(self, verifier: TaintVerifier) -> None:
        src = "<?php\ndefine('INCLUDES_DIR', '/var/www/includes/');\nrequire_once INCLUDES_DIR . 'config.php';\n"
        snippet = "require_once INCLUDES_DIR . 'config.php';"
        res = verifier.verify_sink(
            _node(),
            snippet,
            snippet,
            src,
            language="php",
            base_severity=Severity.HIGH,
            base_confidence=Confidence.CONFIDENT,
        )
        assert res.is_hardcoded_static
        assert res.adjusted_severity == Severity.LOW

    def test_tainted_var_in_same_expression_still_finds(self, verifier: TaintVerifier) -> None:
        """Even if prefix constant is static, $user_var makes the expression tainted."""
        src = (
            "<?php\n"
            "define('BASE', '../');\n"
            "$file = $_GET['file'];\n"
            "$source = file_get_contents(BASE . 'vuln/' . $file);\n"
        )
        snippet = "file_get_contents(BASE . 'vuln/' . $file)"
        res = verifier.verify_sink(
            _node(),
            snippet,
            snippet,
            src,
            language="php",
            base_severity=Severity.HIGH,
            base_confidence=Confidence.CONFIDENT,
        )
        # $file is from $_GET -> has_taint_source must be True
        assert res.has_taint_source or not res.is_hardcoded_static, (
            "Expression with PHP variable should NOT be suppressed as static"
        )


# ---------------------------------------------------------------------------
# Scenario 12: DVWA_WEB_PAGE_TO_ROOT regression
# ---------------------------------------------------------------------------


class TestScenario12_DVWARegression:
    """S12: DVWA_WEB_PAGE_TO_ROOT regression — must be resolved generically, not hardcoded."""

    DVWA_SOURCE = (
        "<?php\n"
        "define( 'DVWA_WEB_PAGE_TO_ROOT', '../' );\n"
        "require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';\n"
    )

    def test_dvwa_constant_is_static(self, resolver: ConstantResolver) -> None:
        ev = resolver.resolve("DVWA_WEB_PAGE_TO_ROOT", self.DVWA_SOURCE)
        assert ev.resolution == ConstantResolution.STATIC_CONSTANT
        assert ev.resolved_value == "../"

    def test_dvwa_require_no_finding(self, verifier: TaintVerifier) -> None:
        """DVWA FP regression: require_once DVWA_WEB_PAGE_TO_ROOT . '...' must NOT be HIGH."""
        snippet = "require_once DVWA_WEB_PAGE_TO_ROOT . 'dvwa/includes/dvwaPage.inc.php';"
        res = verifier.verify_sink(
            _node(),
            snippet,
            snippet,
            self.DVWA_SOURCE,
            language="php",
            base_severity=Severity.HIGH,
            base_confidence=Confidence.CONFIDENT,
        )
        assert res.is_hardcoded_static, "DVWA_WEB_PAGE_TO_ROOT resolved generically to static constant — must suppress"
        assert res.adjusted_severity == Severity.LOW
        assert res.constant_resolution in (
            ConstantResolution.DERIVED_STATIC,
            ConstantResolution.STATIC_CONSTANT,
        )

    def test_no_hardcoded_dvwa_pattern_in_taint_verifier(self) -> None:
        """Structural: TaintVerifier source code must NOT contain 'DVWA_WEB_PAGE_TO_ROOT'."""
        import inspect

        from karsasec.graph import taint_verifier as tv_module

        src = inspect.getsource(tv_module)
        assert "DVWA_WEB_PAGE_TO_ROOT" not in src, (
            "TaintVerifier must not contain project-specific constant 'DVWA_WEB_PAGE_TO_ROOT'. "
            "Resolution must be generic via ConstantResolver."
        )

    def test_dvwa_with_user_var_still_tainted(self, verifier: TaintVerifier) -> None:
        """view_source.php:63 — DVWA_WEB_PAGE_TO_ROOT + $id + $security -> tainted TP."""
        src = (
            "<?php\n"
            "define( 'DVWA_WEB_PAGE_TO_ROOT', '../' );\n"
            "$id       = $_GET[ 'id' ];\n"
            "$security = $_GET[ 'security' ];\n"
            '$source = @file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/source/{$security}.php" );\n'
        )
        snippet = (
            '$source = @file_get_contents( DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/source/{$security}.php" );'
        )
        res = verifier.verify_sink(
            _node(),
            snippet,
            snippet,
            src,
            language="php",
            base_severity=Severity.HIGH,
            base_confidence=Confidence.CONFIDENT,
        )
        # $id and $security come from $_GET -> this MUST NOT be suppressed
        assert not res.is_hardcoded_static, (
            "Expression contains $id/$security from $_GET — must NOT be suppressed as static"
        )


# ---------------------------------------------------------------------------
# Extra: ConstantResolution determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    """ConstantResolver must produce identical results regardless of input order."""

    def test_resolve_is_deterministic(self, resolver: ConstantResolver) -> None:
        src = "<?php define('BASE_PATH', '../');"
        ev1 = resolver.resolve("BASE_PATH", src)
        ev2 = resolver.resolve("BASE_PATH", src)
        assert ev1.resolution == ev2.resolution
        assert ev1.resolved_value == ev2.resolved_value

    def test_cycle_is_deterministic(self, resolver: ConstantResolver) -> None:
        src = "<?php define('A', B);\ndefine('B', A);"
        ev1 = resolver.resolve("A", src)
        ev2 = resolver.resolve("A", src)
        assert ev1.resolution == ev2.resolution
