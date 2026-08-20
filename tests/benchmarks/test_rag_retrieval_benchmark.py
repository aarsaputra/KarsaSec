"""Benchmark suite comparing BM25, Model2Vec, and hybrid RAG retrieval latency."""

import time

from karsasec.rag.bm25 import BM25Document, BM25Index
from karsasec.rag.hybrid import HybridRAGIndex
from karsasec.rag.model2vec import Model2VecEncoder, Model2VecSimilarity


def _build_security_corpus() -> list[BM25Document]:
    sample_texts = [
        "use prepared statements to prevent sql injection and database leak",
        "validate redirect URLs to avoid ssrf and open redirect vulnerabilities",
        "sanitize file upload paths and enforce content-type restrictions",
        "protect against command injection when invoking shell utilities",
        "remove hard-coded credentials and secret tokens from source code",
        "apply rate limiting and authorization checks for broken access control",
        "detect insecure deserialization in serialized object streams",
        "use strict CSP headers to mitigate cross-site scripting attacks",
        "restrict use of eval and dynamic code execution in javascript",
        "verify input encoding and escaping for sql and html contexts",
    ]

    documents = []
    for idx, text in enumerate(sample_texts, start=1):
        documents.append(BM25Document(document_id=f"doc_{idx}", text=text, metadata={"source": "benchmark"}))

    # Duplicate and vary data to simulate larger corpus size
    for idx in range(11, 61):
        base = sample_texts[(idx - 1) % len(sample_texts)]
        documents.append(
            BM25Document(
                document_id=f"doc_{idx}",
                text=f"{base} additional context for retrieval {idx}",
                metadata={"source": "benchmark"},
            )
        )

    return documents


def test_benchmark_rag_retrieval_latency() -> None:
    """Benchmark the latency of BM25, Model2Vec, and Hybrid retrieval on a sample corpus."""
    documents = _build_security_corpus()
    query = "ssrf redirect validation"

    bm25_index = BM25Index(documents)
    encoder = Model2VecEncoder()
    similarity = Model2VecSimilarity(encoder)
    hybrid_index = HybridRAGIndex(documents)

    start = time.perf_counter()
    bm25_results = bm25_index.search(query, top_k=5)
    bm25_elapsed = time.perf_counter() - start

    query_vector = encoder.encode(query)
    start = time.perf_counter()
    model2vec_scores = []
    for doc in documents:
        doc_vector = encoder.encode(doc.text)
        score = similarity.encoder.cosine_similarity(query_vector, doc_vector)
        model2vec_scores.append((doc.document_id, score))
    model2vec_scores.sort(key=lambda item: item[1], reverse=True)
    model2vec_elapsed = time.perf_counter() - start

    start = time.perf_counter()
    hybrid_results = hybrid_index.retrieve(query, top_k=5)
    hybrid_elapsed = time.perf_counter() - start

    print(
        f"\n[RAG Benchmark] BM25 {bm25_elapsed:.5f}s, Model2Vec {model2vec_elapsed:.5f}s, Hybrid {hybrid_elapsed:.5f}s"
    )

    assert bm25_results, "BM25 should return results for the sample security query"
    assert hybrid_results, "Hybrid RAG should return results for the sample security query"
    assert bm25_elapsed < 0.5, f"BM25 retrieval took too long: {bm25_elapsed:.3f}s"
    assert model2vec_elapsed < 0.5, f"Model2Vec retrieval took too long: {model2vec_elapsed:.3f}s"
    assert hybrid_elapsed < 1.0, f"Hybrid retrieval took too long: {hybrid_elapsed:.3f}s"
