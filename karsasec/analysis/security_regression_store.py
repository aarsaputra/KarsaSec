"""Thread-safe SecurityRegressionStore with lock-protected insert-if-absent and index lookups for Sprint E14."""

from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Sequence

from karsasec.analysis.regression_fingerprint import RegressionFingerprint


class SecurityRegressionStore:
    """Thread-safe immutable-facing store for RegressionFingerprint records."""

    def __init__(self, fingerprints: Sequence[RegressionFingerprint] | None = None) -> None:
        self._lock = threading.RLock()
        self._by_id: dict[str, RegressionFingerprint] = {}
        self._by_cluster: dict[str, list[RegressionFingerprint]] = defaultdict(list)
        self._by_class: dict[str, list[RegressionFingerprint]] = defaultdict(list)
        self._by_sink: dict[str, list[RegressionFingerprint]] = defaultdict(list)

        if fingerprints:
            for fp in fingerprints:
                self.add(fp)

    def add(self, fingerprint: RegressionFingerprint) -> bool:
        """Adds a fingerprint atomically (insert-if-absent). Returns True if new record added."""
        with self._lock:
            if fingerprint.fingerprint_id in self._by_id:
                return False

            self._by_id[fingerprint.fingerprint_id] = fingerprint
            self._by_cluster[fingerprint.cluster_id].append(fingerprint)
            self._by_class[fingerprint.vulnerability_class].append(fingerprint)
            self._by_sink[fingerprint.sink_category].append(fingerprint)
            return True

    def get(self, fingerprint_id: str) -> RegressionFingerprint | None:
        """Retrieves a fingerprint by ID."""
        with self._lock:
            return self._by_id.get(fingerprint_id)

    def contains(self, fingerprint_id: str) -> bool:
        """Checks if fingerprint exists in store."""
        with self._lock:
            return fingerprint_id in self._by_id

    def find_by_cluster(self, cluster_id: str) -> tuple[RegressionFingerprint, ...]:
        """Finds fingerprints by cluster_id sorted deterministically."""
        with self._lock:
            records = self._by_cluster.get(cluster_id, [])
            return tuple(sorted(records, key=lambda f: f.fingerprint_id))

    def find_by_class(self, vulnerability_class: str) -> tuple[RegressionFingerprint, ...]:
        """Finds fingerprints by vulnerability_class sorted deterministically."""
        with self._lock:
            records = self._by_class.get(vulnerability_class, [])
            return tuple(sorted(records, key=lambda f: f.fingerprint_id))

    def deterministic_items(self) -> tuple[RegressionFingerprint, ...]:
        """Returns all stored fingerprints sorted deterministically by fingerprint_id."""
        with self._lock:
            return tuple(sorted(self._by_id.values(), key=lambda f: f.fingerprint_id))

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)
