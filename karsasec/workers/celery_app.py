"""Celery integration and task registration for Sprint F2."""

from __future__ import annotations

import os
from typing import Any
from celery import Celery

celery_app = Celery(
    "karsasec",
    broker=os.getenv("CELERY_BROKER_URL", "redis://127.0.0.1:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://127.0.0.1:6379/0"),
)


@celery_app.task(name="karsasec.workers.celery_app.execute_remediation_task")
def execute_remediation_task(task_id: str) -> dict[str, Any]:
    """Celery-compatible task wrapping E13 execution."""
    return {"task_id": task_id, "status": "CELERY_EXECUTION_STUB"}
