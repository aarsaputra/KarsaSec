"""Redis reliable queue implementation for Sprint F2.

Uses BRPOPLPUSH pattern (main and processing queues) to ensure no task is lost.
"""

from __future__ import annotations

from typing import Any

from karsasec.workers.queue import TaskQueue


class RedisTaskQueue(TaskQueue):
    """Reliable task queue using Redis.

    Underlying queue structures:
      - Main Queue: RPUSH / BRPOPLPUSH
      - Processing Queue: tracks active tasks for crash recovery
    """

    def __init__(
        self,
        redis_client: Any,
        queue_name: str = "karsasec:queue:main",
        processing_name: str = "karsasec:queue:processing",
    ) -> None:
        self.r = redis_client
        self.queue_name = queue_name
        self.processing_name = processing_name

    def enqueue(self, task_id: str) -> None:
        """RPUSH to main queue."""
        self.r.rpush(self.queue_name, task_id)

    def dequeue(self, timeout: int = 1) -> str | None:
        """BRPOPLPUSH from main to processing queue."""
        val = self.r.brpoplpush(self.queue_name, self.processing_name, timeout=timeout)
        if val:
            return val.decode("utf-8") if isinstance(val, bytes) else str(val)
        return None

    def acknowledge(self, task_id: str) -> None:
        """LREM from processing queue."""
        self.r.lrem(self.processing_name, 0, task_id)

    def requeue(self, task_id: str) -> None:
        """Requeue a task from processing back to main queue atomically."""
        pipe = self.r.pipeline()
        pipe.lrem(self.processing_name, 0, task_id)
        pipe.lpush(self.queue_name, task_id)
        pipe.execute()

    def get_processing_tasks(self) -> list[str]:
        """Returns all task IDs currently in the processing list."""
        vals = self.r.lrange(self.processing_name, 0, -1)
        return [v.decode("utf-8") if isinstance(v, bytes) else str(v) for v in vals]
