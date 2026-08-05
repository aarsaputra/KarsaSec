from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from math import log
from typing import Dict, Iterable, List, Optional

from karsasec.rag.utils import tokenize_text


@dataclass(frozen=True)
class BM25Document:
    document_id: str
    text: str
    metadata: Dict[str, str]


@dataclass(frozen=True)
class BM25Result:
    document_id: str
    score: float
    text: str
    metadata: Dict[str, str]


class BM25Index:
    def __init__(self, documents: Iterable[BM25Document], k1: float = 1.5, b: float = 0.75) -> None:
        self.documents = list(documents)
        self.k1 = k1
        self.b = b
        self.doc_len: Dict[str, int] = {}
        self.average_doc_len = 0.0
        self.doc_freq: Dict[str, int] = defaultdict(int)
        self.term_freqs: Dict[str, Counter[str]] = {}
        self._build_index()

    def _build_index(self) -> None:
        if not self.documents:
            return

        total_len = 0
        for doc in self.documents:
            tokens = tokenize_text(doc.text)
            self.doc_len[doc.document_id] = len(tokens)
            total_len += len(tokens)

            counts = Counter(tokens)
            self.term_freqs[doc.document_id] = counts
            for token in counts.keys():
                self.doc_freq[token] += 1

        self.average_doc_len = total_len / len(self.documents)

    def _score(self, query_tokens: List[str], document: BM25Document) -> float:
        score = 0.0
        frequencies = self.term_freqs.get(document.document_id, Counter())
        doc_length = self.doc_len.get(document.document_id, 0)

        for token in query_tokens:
            if token not in frequencies:
                continue
            df = self.doc_freq.get(token, 0)
            if df == 0:
                continue
            idf = log((len(self.documents) - df + 0.5) / (df + 0.5) + 1)
            term_freq = frequencies[token]
            numerator = term_freq * (self.k1 + 1)
            denominator = term_freq + self.k1 * (1 - self.b + self.b * (doc_length / max(1.0, self.average_doc_len)))
            score += idf * (numerator / denominator)

        return score

    def search(self, query: str, top_k: int = 5) -> List[BM25Result]:
        query_tokens = tokenize_text(query)
        if not query_tokens or not self.documents:
            return []

        scores: List[BM25Result] = []
        for document in self.documents:
            score = self._score(query_tokens, document)
            if score > 0.0:
                scores.append(BM25Result(document_id=document.document_id, score=score, text=document.text, metadata=document.metadata))

        scores.sort(key=lambda item: item.score, reverse=True)
        return scores[:top_k]
