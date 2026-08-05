"""Unit tests for the taint verifier used by rule evidence analysis."""

from pathlib import Path

from karsasec.graph.taint_verifier import taint_verifier


def test_java_args_index_taint_is_detected() -> None:
    """Java user input via args index should be recognized as taint."""
    file_path = Path("security_corpus/java/ssrf/vulnerable/sample.java")
    source_text = file_path.read_text()
    snippet = "URL url = new URL(target);"
    lines = source_text.splitlines()
    line_num = 7
    start_idx = max(0, line_num - 1 - 10)
    end_idx = min(len(lines), line_num + 10)
    context_text = "\n".join(lines[start_idx:end_idx])

    result = taint_verifier.verify_sink(
        node=None,
        snippet=snippet,
        context_text=context_text,
        source_text=source_text,
        language="Java",
    )

    assert result.has_taint_source is True
    assert "untrusted source" in result.reason.lower()


def test_java_literal_target_is_not_tainted() -> None:
    """Java hardcoded URL assignment should not be treated as taint."""
    file_path = Path("security_corpus/java/ssrf/safe/sample.java")
    source_text = file_path.read_text()
    snippet = "URL url = new URL(target);"
    lines = source_text.splitlines()
    line_num = 7
    start_idx = max(0, line_num - 1 - 10)
    end_idx = min(len(lines), line_num + 10)
    context_text = "\n".join(lines[start_idx:end_idx])

    result = taint_verifier.verify_sink(
        node=None,
        snippet=snippet,
        context_text=context_text,
        source_text=source_text,
        language="Java",
    )

    assert result.has_taint_source is False
    assert result.is_hardcoded_static is False
    assert "no untrusted source" in result.reason.lower()


def test_rust_env_args_taint_is_detected() -> None:
    """Rust env::args user input should be recognized as taint."""
    file_path = Path("security_corpus/rust/ssrf/vulnerable/sample.rs")
    source_text = file_path.read_text()
    snippet = "let response = reqwest::blocking::get(&url);"
    lines = source_text.splitlines()
    line_num = 4
    start_idx = max(0, line_num - 1 - 10)
    end_idx = min(len(lines), line_num + 10)
    context_text = "\n".join(lines[start_idx:end_idx])

    result = taint_verifier.verify_sink(
        node=None,
        snippet=snippet,
        context_text=context_text,
        source_text=source_text,
        language="Rust",
    )

    assert result.has_taint_source is True
    assert "untrusted source" in result.reason.lower()
