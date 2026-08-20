"""ClusterScheduler & ConsistentHashScheduler for Sprint F4/F5.

ConsistentHashScheduler implements SHA-256 ring hashing with Virtual Nodes (default 128 vnodes)
providing stable worker placement under node churn without Python process hash randomization.

Complexity:
  Add worker    : O(V log V)
  Remove worker : O(V log V)
  Assign task   : O(log V) via bisect_right

Note: Consistent Hashing determines deterministic task placement.
PostgreSQL remains the authoritative owner of task state and lease management.
"""

from __future__ import annotations

import hashlib
import threading
from bisect import bisect_right
from typing import Optional, TYPE_CHECKING, Tuple, Set, Dict, List

if TYPE_CHECKING:
    from karsasec.workers.worker_registry import WorkerRegistry, WorkerNode


class ClusterScheduler:
    """Deterministic Round-Robin Cluster Scheduler."""

    def __init__(self, registry: "WorkerRegistry") -> None:
        self._registry = registry
        self._counter: int = 0
        self._lock = threading.Lock()

    def select_worker(self, task_id: str | None = None) -> Optional["WorkerNode"]:
        """Select a healthy worker for a task using Round-Robin v1."""
        active_workers = self._registry.list_active()
        if not active_workers:
            return None

        with self._lock:
            index = self._counter % len(active_workers)
            self._counter += 1
            return active_workers[index]

    def reset_counter(self) -> None:
        """Reset internal round-robin counter."""
        with self._lock:
            self._counter = 0


class NoWorkersAvailableError(RuntimeError):
    """Raised when task assignment is attempted without workers in the hash ring."""
    pass


class ConsistentHashRing:
    """Deterministic SHA-256 Consistent Hash Ring.

    Complexity:
        add_worker    : O(V log V)
        remove_worker : O(V log V)
        assign        : O(log V) via bisect_right

    V = number of virtual nodes per worker (default 128).
    """

    def __init__(self, virtual_nodes: int = 128) -> None:
        if virtual_nodes <= 0:
            raise ValueError("virtual_nodes must be > 0")

        self.virtual_nodes = virtual_nodes
        self._ring: Dict[int, str] = {}
        self._positions: List[int] = []
        self._workers: Set[str] = set()

    @staticmethod
    def _hash(value: str) -> int:
        digest = hashlib.sha256(value.encode("utf-8")).digest()
        return int.from_bytes(digest, byteorder="big", signed=False)

    def add_worker(self, worker_id: str) -> None:
        if not worker_id:
            raise ValueError("worker_id must not be empty")

        if worker_id in self._workers:
            return

        for vnode in range(self.virtual_nodes):
            key = f"{worker_id}#vnode-{vnode}"
            position = self._hash(key)

            while position in self._ring:
                key += "#collision"
                position = self._hash(key)

            self._ring[position] = worker_id

        self._workers.add(worker_id)
        self._positions = sorted(self._ring.keys())

    def remove_worker(self, worker_id: str) -> None:
        if worker_id not in self._workers:
            return

        positions_to_remove = [pos for pos, owner in self._ring.items() if owner == worker_id]
        for pos in positions_to_remove:
            del self._ring[pos]

        self._workers.remove(worker_id)
        self._positions = sorted(self._ring.keys())

    def assign(self, task_id: str) -> str:
        if not self._positions:
            raise NoWorkersAvailableError(
                "No workers available for task assignment"
            )

        position = self._hash(task_id)
        index = bisect_right(self._positions, position)

        if index == len(self._positions):
            index = 0

        return self._ring[self._positions[index]]

    @property
    def workers(self) -> frozenset[str]:
        return frozenset(self._workers)


class ConsistentHashScheduler:
    """Authoritative Consistent Hashing Scheduler using SHA-256 ring + Virtual Nodes (default 128)."""

    def __init__(
        self,
        registry: Optional["WorkerRegistry"] = None,
        virtual_nodes: int = 128,
        replica_count: Optional[int] = None,
    ) -> None:
        vnodes = virtual_nodes if replica_count is None else replica_count
        self._ring = ConsistentHashRing(virtual_nodes=vnodes)
        self._registry = registry
        self._lock = threading.Lock()

    @property
    def virtual_nodes(self) -> int:
        return self._ring.virtual_nodes

    def add_worker(self, worker_id: str) -> None:
        with self._lock:
            self._ring.add_worker(worker_id)

    def remove_worker(self, worker_id: str) -> None:
        with self._lock:
            self._ring.remove_worker(worker_id)

    def assign(self, task_id: str) -> str:
        with self._lock:
            try:
                return self._ring.assign(task_id)
            except NoWorkersAvailableError:
                raise RuntimeError("No workers available")

    def select_worker(self, task_id: str | None = None) -> Optional["WorkerNode"]:
        """Select worker for WorkerRegistry integration."""
        if not self._registry:
            if not self._ring.workers:
                return None
            tid = task_id or "default-task"
            assigned_id = self.assign(tid)
            from karsasec.workers.worker_registry import WorkerNode, WorkerStatus
            node = WorkerNode(worker_id=assigned_id, hostname="localhost")
            node.status = WorkerStatus.ONLINE
            return node

        active_workers = self._registry.list_active()
        if not active_workers:
            return None

        active_ids = {w.worker_id for w in active_workers}
        worker_map = {w.worker_id: w for w in active_workers}

        with self._lock:
            current_workers = set(self._ring.workers)
            for wid in current_workers - active_ids:
                self._ring.remove_worker(wid)
            for w in active_workers:
                if w.worker_id not in self._ring.workers:
                    self._ring.add_worker(w.worker_id)

        target_task_id = task_id or "default-task-id"
        assigned_worker_id = self.assign(target_task_id)
        return worker_map.get(assigned_worker_id, active_workers[0])

    @property
    def workers(self) -> Tuple[str, ...]:
        """Return tuple of active worker IDs."""
        with self._lock:
            return tuple(sorted(self._ring.workers))

