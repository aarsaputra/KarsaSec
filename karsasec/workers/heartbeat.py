"""HeartbeatEngine — Background Worker Health Monitoring Engine (Sprint F4).

Monitors worker heartbeat timestamps registered in WorkerRegistry.

Threshold Configuration:
  - Heartbeat Interval: 30 seconds (expected periodic update)
  - Degraded Threshold: 45 seconds without heartbeat
  - Offline Threshold: 90 seconds without heartbeat

Worker Status Transitions:
  - Last heartbeat <= 45s  -> ONLINE
  - 45s < last heartbeat <= 90s -> DEGRADED
  - Last heartbeat > 90s  -> OFFLINE
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from karsasec.workers.worker_registry import WorkerRegistry


class HeartbeatEngine:
    """Monitors worker heartbeats and transitions worker statuses."""

    HEARTBEAT_INTERVAL_SECONDS = 30.0
    DEGRADED_THRESHOLD_SECONDS = 45.0
    OFFLINE_THRESHOLD_SECONDS = 90.0

    def __init__(self, registry: "WorkerRegistry") -> None:
        self._registry = registry

    def evaluate_workers(self, current_time: float | None = None) -> int:
        """Scan all registered workers and update their status based on heartbeat age.

        Returns:
            Number of workers marked OFFLINE or DEGRADED.
        """
        now = current_time if current_time is not None else time.time()
        workers = self._registry.list_all()
        status_changes = 0

        for worker in workers:
            age = now - worker.last_heartbeat
            from karsasec.workers.worker_registry import WorkerStatus

            if age > self.OFFLINE_THRESHOLD_SECONDS:
                if worker.status != WorkerStatus.OFFLINE:
                    worker.status = WorkerStatus.OFFLINE
                    status_changes += 1
            elif age > self.DEGRADED_THRESHOLD_SECONDS:
                if worker.status != WorkerStatus.DEGRADED:
                    worker.status = WorkerStatus.DEGRADED
                    status_changes += 1
            else:
                if worker.status != WorkerStatus.ONLINE:
                    worker.status = WorkerStatus.ONLINE
                    status_changes += 1

        return status_changes
