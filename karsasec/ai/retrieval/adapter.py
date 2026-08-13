"""Deterministic RAG Knowledge Retrieval Adapter reusing karsasec.rag infrastructure (E13-1)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from karsasec.rag.hybrid import RAGResult
from karsasec.rag.service import RAGDocument, RAGService


@dataclass(frozen=True)
class KnowledgeChunk:
    """Immutable knowledge chunk retrieved from security documentation or rule specifications."""

    document_id: str
    chunk_id: str
    source: str
    title: str
    content: str
    relevance_score: float
    rank: int
    content_hash: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RetrievalResult:
    """Container for retrieval execution results with deterministic ordering."""

    query: str
    chunks: tuple[KnowledgeChunk, ...]
    total_count: int


class KnowledgeRetrieverProtocol(Protocol):
    """Protocol defining the knowledge retrieval contract."""

    def retrieve(
        self,
        query: str,
        filters: dict[str, str] | None = None,
        top_k: int = 5,
    ) -> RetrievalResult:
        ...


class KnowledgeRetrieverAdapter:
    """Knowledge retriever wrapping karsasec.rag with deterministic tie-breaking sorting (E13-1)."""

    def __init__(self, rag_service: RAGService | None = None, documents: list[RAGDocument] | None = None) -> None:
        if rag_service is not None:
            self._service = rag_service
        elif documents is not None:
            self._service = RAGService(documents)
        else:
            # Default empty knowledge base initialized gracefully
            self._service = RAGService([])

    @classmethod
    def from_directory(cls, corpus_dir: Path, force_rebuild: bool = False) -> KnowledgeRetrieverAdapter:
        """Constructs a retriever from a local directory using RAGService."""
        if not corpus_dir.exists() or not corpus_dir.is_dir():
            return cls([])
        service = RAGService.from_directory(corpus_dir, force_rebuild=force_rebuild)
        return cls(service)

    @classmethod
    def from_static_knowledge(cls, items: list[dict[str, str]]) -> KnowledgeRetrieverAdapter:
        """Constructs a retriever from static security rules, CWE, or OWASP knowledge dictionaries."""
        docs: list[RAGDocument] = []
        for idx, item in enumerate(items, start=1):
            doc_id = item.get("id", f"doc:{idx}")
            title = item.get("title", item.get("cwe_id", "Security Guidance"))
            content = item.get("content", item.get("description", ""))
            docs.append(
                RAGDocument(
                    document_id=doc_id,
                    text=f"{title}\n{content}",
                    metadata={
                        "title": title,
                        "cwe_id": item.get("cwe_id", ""),
                        "owasp": item.get("owasp", ""),
                        "category": item.get("category", "GUIDANCE"),
                    },
                )
            )
        return cls(documents=docs)

    def retrieve(
        self,
        query: str,
        filters: dict[str, str] | None = None,
        top_k: int = 5,
    ) -> RetrievalResult:
        if not query.strip():
            return RetrievalResult(query=query, chunks=(), total_count=0)

        # Retrieve raw RAG results from hybrid BM25 + Model2Vec index
        raw_results: list[RAGResult] = self._service.retrieve(query, top_k=top_k * 3)

        # Filter if filters dictionary provided
        filtered: list[RAGResult] = []
        for res in raw_results:
            if filters:
                match = True
                for k, v in filters.items():
                    if res.metadata.get(k, "").upper() != v.upper():
                        match = False
                        break
                if not match:
                    continue
            filtered.append(res)

        # DETERMINISTIC TIE-BREAKING SORTING:
        # Score DESC, document_id ASC, chunk index ASC
        def _sort_key(item: RAGResult) -> tuple[float, str, str]:
            score_neg = -float(item.score)
            doc_id = str(item.document_id)
            chunk_idx = str(item.metadata.get("chunk_index", "0"))
            return (score_neg, doc_id, chunk_idx)

        sorted_results = sorted(filtered, key=_sort_key)
        final_results = sorted_results[:top_k]

        chunks: list[KnowledgeChunk] = []
        for rank, res in enumerate(final_results, start=1):
            content_hash = hashlib.sha256(res.text.encode("utf-8")).hexdigest()[:16]
            title = res.metadata.get("title", res.metadata.get("source_file", "Knowledge Chunk"))
            chunk_id = f"{res.document_id}#chunk{rank}"
            chunks.append(
                KnowledgeChunk(
                    document_id=res.document_id,
                    chunk_id=chunk_id,
                    source=res.metadata.get("source_path", res.document_id),
                    title=title,
                    content=res.text.strip(),
                    relevance_score=round(res.score, 4),
                    rank=rank,
                    content_hash=content_hash,
                    metadata=res.metadata,
                )
            )

        return RetrievalResult(query=query, chunks=tuple(chunks), total_count=len(chunks))
