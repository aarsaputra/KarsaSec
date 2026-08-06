from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from karsasec.rag.bm25 import BM25Document, BM25Index, BM25Result
from karsasec.rag.model2vec import Model2VecEncoder, Model2VecSimilarity


@dataclass(frozen=True)
class RAGResult:
    document_id: str
    score: float
    text: str
    metadata: dict[str, str]


class ReciprocalRankFusion:
    def __init__(self, k: int = 60) -> None:
        self.k = k

    def fuse(self, ranked_lists: list[list[BM25Result or RAGResult]]) -> dict[str, float]:
        fused_scores: dict[str, float] = {}
        for ranking in ranked_lists:
            for position, item in enumerate(ranking, start=1):
                fused_scores[item.document_id] = fused_scores.get(item.document_id, 0.0) + 1.0 / (self.k + position)
        return fused_scores


class HybridRAGIndex:
    def __init__(self, documents: Iterable[BM25Document]) -> None:
        self.documents = list(documents)
        self.bm25_index = BM25Index(self.documents)
        self.encoder = Model2VecEncoder()
        self.similarity = Model2VecSimilarity(self.encoder)
        self.document_embeddings: dict[str, Mapping[int, float]] = {
            doc.document_id: self.encoder.encode(doc.text)
            for doc in self.documents
        }

    def retrieve(self, query: str, top_k: int = 5) -> list[RAGResult]:
        bm25_results = self.bm25_index.search(query, top_k=top_k * 2)
        query_embedding = self.encoder.encode(query)

        embedding_results: list[RAGResult] = []
        for doc in self.documents:
            vector = self.document_embeddings.get(doc.document_id, {})
            if not vector:
                continue
            similarity = self.similarity.encoder.cosine_similarity(query_embedding, vector)
            if similarity > 0.0:
                embedding_results.append(RAGResult(document_id=doc.document_id, score=similarity, text=doc.text, metadata=doc.metadata))

        embedding_results.sort(key=lambda item: item.score, reverse=True)
        embedding_results = embedding_results[: top_k * 2]

        rrf = ReciprocalRankFusion()
        fused = rrf.fuse([bm25_results, embedding_results])

        combined: list[RAGResult] = []
        for doc in self.documents:
            score = fused.get(doc.document_id)
            if score is not None and score > 0.0:
                combined.append(RAGResult(document_id=doc.document_id, score=score, text=doc.text, metadata=doc.metadata))

        combined.sort(key=lambda item: item.score, reverse=True)
        return combined[:top_k]
