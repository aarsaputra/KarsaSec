"""Unit tests for DiffConsoleFormatter."""

from karsasec.ai.remediation.models import PatchHunk
from karsasec.cli.formatters.diff_formatter import DiffConsoleFormatter


def test_diff_console_formatter_plain_text():
    hunk = PatchHunk(
        file_path="web_xss/index.php",
        start_line=281,
        end_line=281,
        original_text="echo $_GET['q'];",
        proposed_text="echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');",
        context="render_search",
        evidence_reference="web_xss/index.php:281",
    )

    output = DiffConsoleFormatter.format_hunk(
        hunk=hunk,
        rule_id="KS-PHP-0028",
        vuln_title="Reflected XSS",
        use_color=False,
    )

    assert "FILE: web_xss/index.php (Line 281)" in output
    assert "RULE: KS-PHP-0028 | Reflected XSS" in output
    assert "-echo $_GET['q'];" in output
    assert "+echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');" in output


def test_diff_console_formatter_colored():
    hunk = PatchHunk(
        file_path="src/app.py",
        start_line=15,
        end_line=15,
        original_text="eval(user_input)",
        proposed_text="ast.literal_eval(user_input)",
        context="eval_node",
        evidence_reference="src/app.py:15",
    )

    output = DiffConsoleFormatter.format_hunk(
        hunk=hunk,
        rule_id="KS-PY-0012",
        vuln_title="Arbitrary Code Execution",
        use_color=True,
    )

    assert "\033[31m-eval(user_input)" in output
    assert "\033[32m+ast.literal_eval(user_input)" in output
