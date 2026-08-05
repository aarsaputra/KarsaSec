import re
from typing import List

_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_'-]+")


def tokenize_text(text: str) -> List[str]:
    """Tokenize text into normalized alphanumeric tokens for search and embedding."""
    return [token.lower() for token in _TOKEN_PATTERN.findall(text) if token.strip()]


def normalize_text(text: str) -> str:
    """Normalize text by tokenizing and rejoining tokens."""
    return " ".join(tokenize_text(text))


def chunk_text(text: str, max_tokens: int = 120) -> List[str]:
    """Split long text into smaller chunks of up to `max_tokens` tokens."""
    tokens = tokenize_text(text)
    if not tokens:
        return []

    if len(tokens) <= max_tokens:
        return [" ".join(tokens)]

    chunks: List[str] = []
    current: List[str] = []
    for token in tokens:
        current.append(token)
        if len(current) >= max_tokens:
            chunks.append(" ".join(current))
            current = []
    if current:
        chunks.append(" ".join(current))
    return chunks
