"""Query Cache providing multi-tier caching for compiled queries, traversals, and results."""

from __future__ import annotations

import time
from typing import Any


class QueryCache:
    """Multi-tier LRU / TTL Query Cache."""

    def __init__(self, max_size: int = 1000, ttl_seconds: float = 300.0) -> None:
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: dict[str, tuple[float, Any]] = {}
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Any | None:
        if key in self._cache:
            created_at, val = self._cache[key]
            if time.time() - created_at <= self.ttl_seconds:
                self._hits += 1
                return val
            del self._cache[key]
        self._misses += 1
        return None

    def put(self, key: str, value: Any) -> None:
        if len(self._cache) >= self.max_size:
            # Evict oldest entry
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][0])
            del self._cache[oldest_key]
        self._cache[key] = (time.time(), value)

    def clear(self) -> None:
        self._cache.clear()
        self._hits = 0
        self._misses = 0

    @property
    def hit_ratio(self) -> float:
        total = self._hits + self._misses
        return (self._hits / total) if total > 0 else 0.0

    def stats(self) -> dict[str, Any]:
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_ratio": self.hit_ratio,
        }
