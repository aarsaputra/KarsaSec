"""FrameworkCache module providing project fingerprinting and caching for framework detection results."""

from __future__ import annotations

import hashlib
from pathlib import Path

from karsasec.framework.models import DetectorResult


class FrameworkCache:
    """Manages SHA-256 fingerprint hash caching for DetectorResult entries."""

    def __init__(self) -> None:
        self._cache: dict[str, list[DetectorResult]] = {}

    @staticmethod
    def compute_fingerprint(paths: list[Path]) -> str:
        """Computes a SHA-256 fingerprint hash for a list of project paths/manifests."""
        hasher = hashlib.sha256()
        for p in sorted(paths, key=lambda x: str(x)):
            if p.exists() and p.is_file():
                hasher.update(p.name.encode("utf-8"))
                hasher.update(str(p.stat().st_mtime).encode("utf-8"))
                try:
                    hasher.update(p.read_bytes()[:1024])
                except OSError:
                    pass
        return hasher.hexdigest()

    def get(self, fingerprint: str) -> list[DetectorResult] | None:
        """Retrieves cached DetectorResult list if present."""
        return self._cache.get(fingerprint)

    def put(self, fingerprint: str, results: list[DetectorResult]) -> None:
        """Stores DetectorResult list under a project fingerprint hash."""
        self._cache[fingerprint] = results

    def clear(self) -> None:
        """Clears the fingerprint cache."""
        self._cache.clear()


framework_cache = FrameworkCache()
