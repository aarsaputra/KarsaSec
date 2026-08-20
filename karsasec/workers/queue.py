"""Abstract TaskQueue Interface and InMemory implementation for Sprint F2."""

from __future__ import annotations

from abc import ABC, abstractmethod
import collections
import threading


class QueueCapacityExceededError(Exception):
    """Raised when queue saturation occurs under heavy backpressure."""
    pass


class TaskQueue(ABC):
    """Interface for async task queuing."""

    @abstractmethod
    def enqueue(self, task_id: str) -> None:
        """Add a task ID to the main queue."""
        pass

    @abstractmethod
    def dequeue(self, timeout: int = 1) -> str | None:
        """Fetch a task ID from the main queue and move it to processing."""
        pass

    @abstractmethod
    def acknowledge(self, task_id: str) -> None:
        """Acknowledge successful completion of a task, removing it from processing."""
        pass

    @abstractmethod
    def requeue(self, task_id: str) -> None:
        """Requeue a task from processing back to main queue."""
        pass


class InMemoryTaskQueue(TaskQueue):
    """Thread-safe in-memory FIFO queue with reliable processing tracking and atomic backpressure.

    Note: `threading.Lock()` provides process-local thread-safety.
    In multi-node cluster production (Sprint F5), Redis list bounds or RabbitMQ queue max-length
    act as the distributed backpressure authority.
    """

    DEFAULT_MAX_QUEUE_DEPTH = 10_000

    def __init__(self, max_queue_depth: int = DEFAULT_MAX_QUEUE_DEPTH) -> None:
        self.main_queue: collections.deque[str] = collections.deque()
        self.processing_queue: list[str] = []
        self.max_queue_depth = max_queue_depth
        self._lock = threading.Lock()

    def enqueue(self, task_id: str) -> None:
        """Atomically checks depth and appends under lock to guarantee max capacity invariant."""
        with self._lock:
            # Point 10: Backpressure Strategy (Queue Saturation Policy under lock)
            if len(self.main_queue) >= self.max_queue_depth:
                raise QueueCapacityExceededError(
                    f"Queue capacity exceeded (MAX_QUEUE_DEPTH={self.max_queue_depth}). Backpressure triggered."
                )
            self.main_queue.append(task_id)

    def dequeue(self, timeout: int = 1) -> str | None:
        with self._lock:
            if self.main_queue:
                task_id = self.main_queue.popleft()
                self.processing_queue.append(task_id)
                return task_id
            return None

    def acknowledge(self, task_id: str) -> None:
        with self._lock:
            if task_id in self.processing_queue:
                self.processing_queue.remove(task_id)

    def requeue(self, task_id: str) -> None:
        with self._lock:
            if task_id in self.processing_queue:
                self.processing_queue.remove(task_id)
            self.main_queue.appendleft(task_id)

    def get_processing_tasks(self) -> list[str]:
        with self._lock:
            return list(self.processing_queue)
