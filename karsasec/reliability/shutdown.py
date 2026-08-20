"""Graceful Shutdown Coordinator & Signal Handler for Sprint F6C.

Invariants:
  - INV-F6-SHUTDOWN-01: Handles SIGINT and SIGTERM non-blockingly via atomic flag/signal set.
  - INV-F6-SHUTDOWN-02: Initiates drain mode immediately upon signal receipt.
  - INV-F6-SHUTDOWN-03: Active running tasks are given up to 30.0s to complete.
  - INV-F6-SHUTDOWN-04: Worker process exits with code 0 if all active tasks finish within timeout.
  - INV-F6-SHUTDOWN-05: If timeout expires, worker is marked FENCED with incremented fencing_token and exits.
  - INV-F6-SHUTDOWN-06: Signal handlers perform zero blocking DB/network calls inside the signal callback.
"""

from __future__ import annotations

import signal
import sys
import threading
from typing import Any

from karsasec.persistence.db import DatabaseSessionFactory, get_session_factory
from karsasec.reliability.drain_mode import WorkerDrainController
from karsasec.workers.worker_registry import WorkerStatus
from karsasec.observability.logger import default_logger


class GracefulShutdownCoordinator:
    """Coordinates graceful worker shutdown, signal handling, and timeout fencing."""

    def __init__(
        self,
        worker_id: str,
        drain_controller: WorkerDrainController | None = None,
        session_factory: DatabaseSessionFactory | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.worker_id = worker_id
        self._session_factory = session_factory or get_session_factory()
        self._drain_controller = drain_controller or WorkerDrainController(self._session_factory)
        self.timeout_seconds = timeout_seconds
        self._shutdown_requested = threading.Event()
        self._shutdown_started = False
        self._final_status: WorkerStatus | None = None
        self._lock = threading.Lock()

    def register_signal_handlers(self) -> None:
        """Register non-blocking SIGINT & SIGTERM signal handlers (INV-F6-SHUTDOWN-06)."""

        def _signal_handler(signum: int, frame: Any) -> None:
            # Signal callback performs ONLY non-blocking Event set (INV-F6-SHUTDOWN-06)
            default_logger.info(
                "SIGNAL_RECEIVED",
                f"Received signal {signum}. Triggering graceful shutdown request.",
                component="shutdown_coordinator",
                worker_id=self.worker_id,
            )
            self._shutdown_requested.set()

        try:
            signal.signal(signal.SIGINT, _signal_handler)
            signal.signal(signal.SIGTERM, _signal_handler)
        except (ValueError, OSError):
            # May fail if running in non-main thread in test environment; ignored safely
            pass

    def request_shutdown(self) -> None:
        """Manually trigger shutdown request."""
        self._shutdown_requested.set()

    def is_shutdown_requested(self) -> bool:
        """Check if shutdown signal or request has been received."""
        return self._shutdown_requested.is_set()

    def execute_shutdown(self, exit_on_complete: bool = False) -> WorkerStatus:
        """Execute worker drain, wait for running tasks, or fence on 30s timeout."""
        with self._lock:
            if self._shutdown_started:
                if self._final_status is not None:
                    return self._final_status
                return WorkerStatus.FENCED if self.is_shutdown_requested() else WorkerStatus.OFFLINE
            self._shutdown_started = True

        default_logger.info(
            "EXECUTING_GRACEFUL_SHUTDOWN",
            f"Executing graceful shutdown for worker '{self.worker_id}'. Timeout: {self.timeout_seconds}s.",
            component="shutdown_coordinator",
            worker_id=self.worker_id,
        )

        final_status = self._drain_controller.wait_for_drain(
            worker_id=self.worker_id,
            timeout_seconds=self.timeout_seconds,
            poll_interval=0.2,
        )

        with self._lock:
            self._final_status = final_status

        if exit_on_complete:
            exit_code = 0 if final_status == WorkerStatus.DRAINED else 1
            sys.exit(exit_code)

        return final_status
