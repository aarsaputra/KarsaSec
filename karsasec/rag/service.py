from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional

from karsasec.config import settings
from karsasec.rag.bm25 import BM25Document
from karsasec.rag.hybrid import HybridRAGIndex, RAGResult
from karsasec.rag.indexer import RAGCorpusBuilder
from karsasec.rag.utils import chunk_text


TEXT_FILE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".go", ".rs", ".java",
    ".yaml", ".yml", ".json", ".md", ".txt", ".dockerfile",
}


@dataclass(frozen=True)
class RAGDocument:
    document_id: str
    text: str
    metadata: Dict[str, str]


class RAGService:
    """Service for building a hybrid RAG index over a local corpus and retrieving context."""

    def __init__(self, documents: Iterable[RAGDocument]) -> None:
        self.documents = list(documents)
        self.hybrid_index = HybridRAGIndex(
            [BM25Document(document_id=doc.document_id, text=doc.text, metadata=doc.metadata) for doc in self.documents]
        )

    @classmethod
    def from_directory(cls, corpus_path: Path, cache_dir: Optional[Path] = None, force_rebuild: bool = False) -> "RAGService":
        cache_root = cache_dir or settings.cache_dir / "rag"
        builder = RAGCorpusBuilder(corpus_path, cache_dir=cache_root)
        documents = builder.build(force_rebuild=force_rebuild)
        return cls(documents)

    @staticmethod
    def _text_file_filter(path: Path) -> bool:
        return path.is_file() and (path.suffix.lower() in TEXT_FILE_EXTENSIONS or path.name.lower() in {"dockerfile", "containerfile"})

    @classmethod
    def _load_corpus(cls, corpus_path: Path) -> Iterator[RAGDocument]:
        if not corpus_path.exists() or not corpus_path.is_dir():
            return

        for file_path in sorted(corpus_path.rglob("*")):
            if not cls._text_file_filter(file_path):
                continue
            try:
                raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            chunks = chunk_text(raw_text, max_tokens=120)
            for index, text_chunk in enumerate(chunks, start=1):
                yield RAGDocument(
                    document_id=f"{file_path.name}:{index}",
                    text=text_chunk,
                    metadata={
                        "source_path": str(file_path.relative_to(corpus_path.parent)),
                        "source_file": file_path.name,
                        "chunk_index": str(index),
                    },
                )

    def retrieve(self, query: str, top_k: int = 5) -> List[RAGResult]:
        return self.hybrid_index.retrieve(query, top_k=top_k)
