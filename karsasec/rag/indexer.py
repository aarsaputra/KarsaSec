from __future__ import annotations

import json
from collections.abc import Iterator
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from karsasec.rag.service import RAGDocument

from karsasec.rag.utils import chunk_text


class RAGCorpusBuilder:
    """Builds and caches a corpus index for hybrid RAG retrieval."""

    def __init__(self, corpus_path: Path, cache_dir: Path | None = None) -> None:
        self.corpus_path = corpus_path
        self.cache_dir = cache_dir or Path.home() / ".karsasec" / "rag"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.documents_path = self.cache_dir / "rag_documents.json"
        self.state_path = self.cache_dir / "rag_corpus_state.json"

    def build(self, force_rebuild: bool = False) -> list[RAGDocument]:
        if not self.corpus_path.exists() or not self.corpus_path.is_dir():
            return []

        state = self._compute_corpus_state()
        if not force_rebuild and self._is_cache_valid(state):
            try:
                return self._load_cached_documents()
            except Exception:
                pass

        documents = list(self._scan_corpus())
        self._write_cache(documents, state)
        return documents

    def _compute_corpus_state(self) -> dict[str, Any]:
        files = sorted(
            p
            for p in self.corpus_path.rglob("*")
            if p.is_file() and p.suffix.lower() in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".go", ".rs", ".java", ".yaml", ".yml", ".json", ".md", ".txt"} or p.name.lower() in {"dockerfile", "containerfile"}
        )
        state: dict[str, Any] = {"files": []}
        for file_path in files:
            relative = str(file_path.relative_to(self.corpus_path))
            stat = file_path.stat()
            state["files"].append(
                {
                    "relative_path": relative,
                    "mtime": stat.st_mtime,
                    "size": stat.st_size,
                }
            )
        state["hash"] = sha256(json.dumps(state["files"], sort_keys=True).encode("utf-8")).hexdigest()
        return state

    def _is_cache_valid(self, current_state: dict[str, Any]) -> bool:
        if not self.documents_path.exists() or not self.state_path.exists():
            return False
        try:
            with self.state_path.open("r", encoding="utf-8") as handle:
                cached_state = json.load(handle)
            return cached_state.get("hash") == current_state.get("hash")
        except Exception:
            return False

    def _load_cached_documents(self) -> list[RAGDocument]:
        from karsasec.rag.service import RAGDocument

        with self.documents_path.open("r", encoding="utf-8") as handle:
            raw_docs = json.load(handle)
        return [RAGDocument(document_id=item["document_id"], text=item["text"], metadata=item["metadata"]) for item in raw_docs]

    def _write_cache(self, documents: list[RAGDocument], state: dict[str, Any]) -> None:
        raw_docs = [
            {"document_id": doc.document_id, "text": doc.text, "metadata": doc.metadata}
            for doc in documents
        ]
        with self.documents_path.open("w", encoding="utf-8") as handle:
            json.dump(raw_docs, handle, ensure_ascii=False, indent=2)
        with self.state_path.open("w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=False, indent=2)

    def _scan_corpus(self) -> Iterator[RAGDocument]:
        from karsasec.rag.service import RAGDocument

        for file_path in sorted(self.corpus_path.rglob("*")):
            if not file_path.is_file():
                continue
            suffix = file_path.suffix.lower()
            if suffix not in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".go", ".rs", ".java", ".yaml", ".yml", ".json", ".md", ".txt"} and file_path.name.lower() not in {"dockerfile", "containerfile"}:
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
                        "source_path": str(file_path.relative_to(self.corpus_path)),
                        "source_file": file_path.name,
                        "chunk_index": str(index),
                    },
                )
