"""Sprint E10-3I: Rule Hardening Tests for KS-OWASP-0010 (SSRF) and KS-OWASP-0001 (Broken Access Control).

Validates that:
- KS-OWASP-0010 no longer triggers on PDO ->fetch(), console.error, lastErrorMsg (FP sources from DVWA)
- KS-OWASP-0010 still triggers on real HTTP fetch / file_get_contents calls
- KS-OWASP-0001 no longer triggers on HTML documentation prose (FP sources from DVWA help.php)
- KS-OWASP-0001 still triggers on real setcookie() / $_COOKIE[] access control code
"""

from pathlib import Path

from karsasec.parser.ast.context import VisitorContext
from karsasec.parser.ast_nodes import ASTNode, FileNode
from karsasec.rules.loader import YAMLRuleLoader
from karsasec.rules.matcher.matcher import ASTMatcher
from karsasec.rules.matcher.predicates.node_text_exclusion import NodeTextExclusionPredicate

RULES_DIR = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns" / "owasp"


def _ctx(file: str = "test.php") -> VisitorContext:
    fn = FileNode(file_path=Path(file), language="PHP")
    return VisitorContext(file_node=fn, file_path=Path(file), language="PHP")


def _node(snippet: str, node_type: str = "call") -> tuple[ASTNode, bytes]:
    encoded = snippet.encode("utf-8")
    return ASTNode(node_type=node_type, byte_start=0, byte_end=len(encoded)), encoded


class TestNodeTextExclusionPredicate:
    """Unit tests for NodeTextExclusionPredicate in isolation."""

    def setup_method(self) -> None:
        self.loader = YAMLRuleLoader()
        self.rule_a10 = self.loader.load_file(RULES_DIR / "A10_ssrf.yaml")

    def test_exclusion_pattern_is_loaded(self) -> None:
        cond = self.rule_a10.condition
        assert cond.node_text_not_matches is not None
        assert "fetch" in cond.node_text_not_matches

    def test_predicate_name(self) -> None:
        pred = NodeTextExclusionPredicate()
        assert pred.name == "NodeTextExclusionPredicate"


class TestSSRFRuleHardening:
    """Tests KS-OWASP-0010 SSRF rule against DVWA-sourced false positives and real SSRF sinks."""

    def setup_method(self) -> None:
        self.loader = YAMLRuleLoader()
        self.matcher = ASTMatcher()
        self.rule = self.loader.load_file(RULES_DIR / "A10_ssrf.yaml")
        self.ctx = _ctx("vuln.php")

    # --- False Positives that MUST be suppressed ---

    def test_pdo_fetch_is_not_ssrf(self) -> None:
        """$row = $data->fetch() must NOT trigger SSRF."""
        node, src = _node("$row = $data->fetch()")
        res = self.matcher.match(node, self.rule, self.ctx, source_bytes=src)
        assert not res.matched, "PDO ->fetch() falsely flagged as SSRF"

    def test_pdo_fetchall_is_not_ssrf(self) -> None:
        node, src = _node("$rows = $stmt->fetchAll(PDO::FETCH_ASSOC)")
        res = self.matcher.match(node, self.rule, self.ctx, source_bytes=src)
        assert not res.matched, "PDO ->fetchAll() falsely flagged as SSRF"

    def test_js_console_error_fetch_is_not_ssrf(self) -> None:
        """console.error('There was a problem with your fetch operation') must NOT trigger."""
        node, src = _node("console.error('There was a problem with your fetch operation:', error)")
        res = self.matcher.match(node, self.rule, self.ctx, source_bytes=src)
        assert not res.matched, "console.error with 'fetch' falsely flagged as SSRF"

    def test_sqlite_last_error_msg_is_not_ssrf(self) -> None:
        """echo 'Error in fetch ' . $sqlite_db->lastErrorMsg() must NOT trigger."""
        node, src = _node('echo "Error in fetch ".$sqlite_db->lastErrorMsg()')
        res = self.matcher.match(node, self.rule, self.ctx, source_bytes=src)
        assert not res.matched, "SQLite lastErrorMsg 'fetch' falsely flagged as SSRF"

    # --- True Positives that MUST still be detected ---

    def test_php_file_get_contents_user_input_is_ssrf(self) -> None:
        """file_get_contents($url) where $url is variable MUST trigger SSRF."""
        node, src = _node("$data = file_get_contents($url)")
        res = self.matcher.match(node, self.rule, self.ctx, source_bytes=src)
        assert res.matched, "file_get_contents($url) must be detected as SSRF"

    def test_js_fetch_with_variable_is_ssrf(self) -> None:
        """fetch(userUrl) MUST trigger SSRF."""
        node, src = _node("fetch(userUrl)")
        res = self.matcher.match(node, self.rule, self.ctx, source_bytes=src)
        assert res.matched, "fetch(userUrl) must be detected as SSRF"

    def test_python_requests_get_is_ssrf(self) -> None:
        node, src = _node("response = requests.get(target_url)")
        res = self.matcher.match(node, self.rule, self.ctx, source_bytes=src)
        assert res.matched, "requests.get(target_url) must be detected as SSRF"

    def test_php_curl_exec_is_ssrf(self) -> None:
        node, src = _node("$result = curl_exec($ch)")
        res = self.matcher.match(node, self.rule, self.ctx, source_bytes=src)
        assert res.matched, "curl_exec($ch) must be detected as SSRF"


class TestBrokenAccessControlRuleHardening:
    """Tests KS-OWASP-0001 A01 rule against DVWA-sourced false positives and real access control sinks."""

    def setup_method(self) -> None:
        self.loader = YAMLRuleLoader()
        self.matcher = ASTMatcher()
        self.rule = self.loader.load_file(RULES_DIR / "A01_broken_access_control.yaml")
        self.ctx = _ctx("help.php")

    # --- False Positives that MUST be suppressed ---

    def test_html_prose_cookie_mention_is_not_a01(self) -> None:
        """HTML documentation text mentioning 'cookies' must NOT trigger A01."""
        snippet = "and will execute the JavaScript. Because it thinks the script came from a trusted source, the malicious script can access any cookies, session tokens, or other"
        node, src = _node(snippet, node_type="call")
        res = self.matcher.match(node, self.rule, self.ctx, source_bytes=src)
        assert not res.matched, "HTML documentation prose falsely flagged as A01"

    def test_html_input_token_attribute_is_not_a01(self) -> None:
        """<input type='hidden' name='token' ...> HTML element must NOT trigger A01."""
        snippet = '<input type="hidden" name="token" value="" id="token" />'
        node, src = _node(snippet, node_type="call")
        res = self.matcher.match(node, self.rule, self.ctx, source_bytes=src)
        assert not res.matched, "HTML input token attribute falsely flagged as A01"

    # --- True Positives that MUST still be detected ---

    def test_setcookie_without_httponly_is_a01(self) -> None:
        """setcookie('dvwaSession', $cookie_value) without secure flags MUST trigger A01."""
        node, src = _node('setcookie("dvwaSession", $cookie_value)', node_type="call")
        res = self.matcher.match(node, self.rule, self.ctx, source_bytes=src)
        assert res.matched, "setcookie() without security flags must be detected as A01"

    def test_cookie_direct_id_assignment_is_a01(self) -> None:
        """$id = $_COOKIE['id'] direct cookie assignment to variable MUST trigger A01."""
        node, src = _node("$id = $_COOKIE['id']", node_type="assignment")
        res = self.matcher.match(node, self.rule, self.ctx, source_bytes=src)
        assert res.matched, "$_COOKIE['id'] direct assignment must be detected as A01"
