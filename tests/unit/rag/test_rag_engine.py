
from karsasec.rag.bm25 import BM25Document, BM25Index
from karsasec.rag.service import RAGDocument, RAGService


def test_bm25_search_ranks_relevant_document_first() -> None:
    documents = [
        BM25Document(document_id="doc1", text="always sanitize user input before database query", metadata={}),
        BM25Document(document_id="doc2", text="static configuration file with default values", metadata={}),
    ]

    index = BM25Index(documents)
    results = index.search("user input query", top_k=2)

    assert results, "BM25 should return at least one result for a matching query"
    assert results[0].document_id == "doc1"
    assert results[0].score > 0.0


def test_model2vec_similarity_orders_semantically_related_texts() -> None:
    rag_service = RAGService(
        [
            RAGDocument(document_id="doc1", text="use prepared statements to prevent sql injection", metadata={}),
            RAGDocument(document_id="doc2", text="this example shows safe file parsing", metadata={}),
        ]
    )

    results = rag_service.retrieve("sql injection prevention", top_k=2)
    assert results, "Hybrid RAG should return results for security query"
    assert results[0].document_id == "doc1"
    if len(results) > 1:
        assert results[0].score >= results[1].score


def test_rag_service_loads_corpus_from_directory(tmp_path) -> None:
    corpus_dir = tmp_path / "security_corpus"
    corpus_dir.mkdir()
    (corpus_dir / "rule_example.md").write_text("Use https to prevent ssrf and insecure redirects.", encoding="utf-8")

    service = RAGService.from_directory(corpus_dir)
    assert service is not None

    results = service.retrieve("ssrf insecure redirect", top_k=1)
    assert len(results) == 1
    assert "ssrf" in results[0].text.lower()


def test_rag_service_force_rebuild_uses_fresh_index(tmp_path) -> None:
    corpus_dir = tmp_path / "security_corpus"
    cache_dir = tmp_path / "cache"
    corpus_dir.mkdir()
    cache_dir.mkdir()

    (corpus_dir / "rule_initial.md").write_text("ssrf mitigation and secure redirects", encoding="utf-8")
    service = RAGService.from_directory(corpus_dir, cache_dir=cache_dir)
    results_initial = service.retrieve("ssrf", top_k=1)
    assert results_initial and "ssrf" in results_initial[0].text.lower()

    (corpus_dir / "rule_new.md").write_text("prevent ssrf by validating redirect URLs", encoding="utf-8")
    service_rebuild = RAGService.from_directory(corpus_dir, cache_dir=cache_dir, force_rebuild=True)
    results_rebuild = service_rebuild.retrieve("ssrf", top_k=2)
    assert len(results_rebuild) >= 1
    assert any("ssrf" in item.text.lower() for item in results_rebuild)
