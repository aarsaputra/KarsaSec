"""Unit tests for KnowledgeRetrieverAdapter and deterministic ordering (E13-1)."""

from __future__ import annotations

from karsasec.ai.retrieval.adapter import KnowledgeRetrieverAdapter


def test_retrieval_static_knowledge_retrieval() -> None:
    items = [
        {
            "id": "CWE-89",
            "title": "SQL Injection",
            "content": "The software constructs an SQL command using externally-influenced input.",
            "cwe_id": "CWE-89",
            "category": "CWE",
        },
        {
            "id": "CWE-79",
            "title": "Cross-site Scripting",
            "content": "The software does not neutralize or incorrectly neutralizes user input before rendering.",
            "cwe_id": "CWE-79",
            "category": "CWE",
        },
    ]

    adapter = KnowledgeRetrieverAdapter.from_static_knowledge(items)
    res = adapter.retrieve(query="SQL Injection query", top_k=2)

    assert len(res.chunks) >= 1
    top_chunk = res.chunks[0]
    assert "SQL" in top_chunk.title or "SQL" in top_chunk.content
    assert top_chunk.rank == 1


def test_retrieval_deterministic_ordering_and_tie_breaking() -> None:
    items = [
        {"id": "doc:B", "title": "Alpha Guidance", "content": "Security query validation guide.", "cwe_id": "CWE-89"},
        {"id": "doc:A", "title": "Alpha Guidance", "content": "Security query validation guide.", "cwe_id": "CWE-89"},
    ]

    adapter = KnowledgeRetrieverAdapter.from_static_knowledge(items)
    res1 = adapter.retrieve(query="Security query validation", top_k=5)
    res2 = adapter.retrieve(query="Security query validation", top_k=5)

    assert [c.document_id for c in res1.chunks] == [c.document_id for c in res2.chunks]
    # Tie breaking order doc:A should precede doc:B when score is identical
    doc_ids = [c.document_id for c in res1.chunks]
    if len(doc_ids) >= 2 and round(res1.chunks[0].relevance_score, 4) == round(res1.chunks[1].relevance_score, 4):
        assert doc_ids[0] <= doc_ids[1]


def test_retrieval_empty_query_or_corpus() -> None:
    adapter = KnowledgeRetrieverAdapter()
    res = adapter.retrieve(query="", top_k=5)
    assert res.total_count == 0
    assert len(res.chunks) == 0

    res_blank = adapter.retrieve(query="SQL Injection", top_k=5)
    assert res_blank.total_count == 0
