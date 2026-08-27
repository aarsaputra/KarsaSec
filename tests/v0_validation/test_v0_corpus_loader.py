"""Unit tests for Phase V0 Corpus Loader."""

from pathlib import Path
from karsasec.validation.v0_corpus_loader import CorpusLoader


def test_corpus_loader_reads_11_categories():
    corpus_dir = Path(__file__).resolve().parent.parent / "v0_corpus"
    samples = CorpusLoader.load_from_dir(corpus_dir)

    assert len(samples) == 11
    categories = {s.category for s in samples}
    assert "sql_injection" in categories
    assert "xss" in categories
    assert "command_injection" in categories
    assert "ssrf" in categories
    assert "path_traversal" in categories
