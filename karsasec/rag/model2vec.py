import hashlib
import math
from collections import Counter
from collections.abc import Mapping

from karsasec.rag.utils import tokenize_text


def stable_token_hash(token: str) -> int:
    return int.from_bytes(hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(), "big")


class Model2VecEncoder:
    """Lightweight static embedding encoder for code/text retrieval."""

    def encode(self, text: str) -> dict[int, float]:
        tokens = tokenize_text(text)
        if not tokens:
            return {}
        counts = Counter(tokens)
        vector: dict[int, float] = {}
        for token, freq in counts.items():
            vector[stable_token_hash(token)] = float(freq)
        return vector

    def cosine_similarity(
        self,
        a: Mapping[int, float],
        b: Mapping[int, float],
    ) -> float:
        if not a or not b:
            return 0.0

        dot_product = 0.0
        for token_id, weight in a.items():
            dot_product += weight * b.get(token_id, 0.0)

        norm_a = math.sqrt(sum(value * value for value in a.values()))
        norm_b = math.sqrt(sum(value * value for value in b.values()))

        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0

        return dot_product / (norm_a * norm_b)


class Model2VecSimilarity:
    """Helper class for static embedding similarity calculations."""

    def __init__(self, encoder: Model2VecEncoder | None = None) -> None:
        self.encoder = encoder or Model2VecEncoder()

    def score(self, query: str, document_text: str) -> float:
        query_vec = self.encoder.encode(query)
        doc_vec = self.encoder.encode(document_text)
        return self.encoder.cosine_similarity(query_vec, doc_vec)
