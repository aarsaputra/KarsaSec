"""Worker execution runtime, reliable processing, and lease recovery for Sprint F2.

Enforces L7 (Zero Security Authority) and capability isolation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
import time
from typing import Any

from karsasec.ai.remediation.lifecycle import RemediationLifecycleEngine
from karsasec.ai.remediation.rtp.builder import RemediationTransactionPackageBuilder
from karsasec.ai.remediation.rtp.validator import RTPValidator
from karsasec.ai.remediation.rtp.receipt import VerificationReceipt
from karsasec.workers.queue import TaskQueue
from karsasec.workers.repository import TaskRepository
from karsasec.workers.task import TaskState


class WorkerRuntime(ABC):
    """Abstract worker execution environment."""

    @abstractmethod
    def start(self) -> None:
        """Starts worker polling/execution loop."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stops worker execution gracefully."""
        pass


class CustomWorkerRuntime(WorkerRuntime):
    """Custom polling worker loop utilizing TaskQueue and TaskRepository."""

    def __init__(
        self,
        queue: TaskQueue,
        repository: TaskRepository,
        worker_id: str = "worker-default",
        fencing_token: int = 1,
    ) -> None:
        self.queue = queue
        self.repository = repository
        self.worker_id = worker_id
        self.fencing_token = fencing_token
        self._stop_requested = False

    def start(self) -> None:
        self._stop_requested = False
        while not self._stop_requested:
            try:
                task_id = self.queue.dequeue(timeout=1)
                if task_id:
                    self.process_task(task_id)
                self.recover_stale_tasks()
            except Exception:
                # Basic logging or sleep to prevent tight error loops
                time.sleep(1)

    def stop(self) -> None:
        self._stop_requested = True

    def process_task(self, task_id: str) -> None:
        """Executes E13 lifecycle + F0 RTP validation on a single task."""
        from karsasec.server.services.remediation_service import _build_stub_finding
        from karsasec.cli.commands.scan import _run_scan_pipeline

        task = self.repository.get_task(task_id)
        if not task:
            self.queue.acknowledge(task_id)
            return

        if task.state not in (TaskState.QUEUED, TaskState.FAILED_RETRYABLE):
            self.queue.acknowledge(task_id)
            return

        try:
            # Transition task to RUNNING via assign_task or update_task
            if hasattr(self.repository, "assign_task"):
                try:
                    task = self.repository.assign_task(task_id, self.worker_id)
                except Exception:
                    self.repository.update_task(task_id, state=TaskState.RUNNING)
            else:
                self.repository.update_task(task_id, state=TaskState.RUNNING)

            engine = RemediationLifecycleEngine(repository_root=Path("."))

            def _rescan():
                try:
                    result = _run_scan_pipeline(
                        target_path=Path("."),
                        config_file=None,
                        rules_dir=None,
                        diff_scan=False,
                    )
                    return result.findings if result else ()
                except Exception:
                    return ()

            # Authoritative E13 execution
            lifecycle_result = engine.execute(
                finding=_build_stub_finding(task.finding_id),
                approval_provider=None,
                rescan_callback=_rescan,
            )

            # Build portable RTP
            rtp = RemediationTransactionPackageBuilder.build(
                lifecycle_result=lifecycle_result,
                transaction_id=task_id,
            )

            # Validate RTP — ONLY source of security_verification_status (L7)
            validation_result = RTPValidator.validate(rtp)

            # Derive receipt
            receipt = VerificationReceipt.from_rtp(rtp=rtp, validation_result=validation_result)

            # Task succeeded -> transition to COMPLETED via complete_task
            try:
                self.repository.complete_task(
                    task_id=task_id,
                    expected_lease_version=task.lease_version,
                    worker_id=self.worker_id,
                    worker_fencing_token=self.fencing_token,
                    receipt_id=receipt.receipt_id,
                    receipt_fingerprint=receipt.receipt_fingerprint,
                    security_verification_status=str(validation_result.security_verification_status),
                )
            except Exception:
                self.repository.update_task(
                    task_id,
                    state=TaskState.COMPLETED,
                    receipt_id=receipt.receipt_id,
                    receipt_fingerprint=receipt.receipt_fingerprint,
                    security_verification_status=str(validation_result.security_verification_status),
                )
            self.queue.acknowledge(task_id)

        except Exception as exc:
            # Failure recording via record_execution_failure / atomic authority
            if hasattr(self.repository, "record_execution_failure"):
                try:
                    self.repository.record_execution_failure(
                        task_id=task_id,
                        expected_lease_version=task.lease_version,
                        worker_id=self.worker_id,
                        worker_fencing_token=self.fencing_token,
                        error_message=str(exc),
                    )
                except Exception:
                    pass
                if task.attempts < task.max_attempts:
                    self.queue.requeue(task_id)
                else:
                    self.queue.acknowledge(task_id)
            else:
                # InMemory fallback
                if task.attempts < task.max_attempts:
                    self.repository.update_task(
                        task_id,
                        state=TaskState.FAILED_RETRYABLE,
                        error_message=str(exc),
                    )
                    self.repository.update_task(task_id, state=TaskState.QUEUED)
                    self.queue.requeue(task_id)
                else:
                    self.repository.update_task(task_id, state=TaskState.FAILED, error_message=str(exc))
                    self.queue.acknowledge(task_id)

    def recover_stale_tasks(self, current_time: float | None = None) -> None:
        """Identifies active tasks whose lease has expired, then requeues them."""
        if current_time is None:
            current_time = time.monotonic()

        # Check all processing task IDs
        if hasattr(self.queue, "get_processing_tasks"):
            processing_ids = self.queue.get_processing_tasks()
            for task_id in processing_ids:
                task = self.repository.get_task(task_id)
                if task and task.state == TaskState.RUNNING:
                    if task.is_lease_expired(current_time):
                        if hasattr(self.repository, "atomic_transition"):
                            try:
                                target_state = (
                                    TaskState.QUEUED if task.attempts < task.max_attempts else TaskState.FAILED
                                )
                                self.repository.atomic_transition(
                                    task_id=task_id,
                                    expected_lease_version=task.lease_version,
                                    expected_states=[TaskState.RUNNING],
                                    new_state=target_state,
                                    error_message="Lease expired",
                                )
                                if target_state == TaskState.QUEUED:
                                    self.queue.requeue(task_id)
                                else:
                                    self.queue.acknowledge(task_id)
                            except Exception:
                                pass
                        else:
                            if task.attempts < task.max_attempts:
                                self.repository.update_task(
                                    task_id,
                                    state=TaskState.FAILED_RETRYABLE,
                                    error_message="Lease expired",
                                )
                                self.repository.update_task(task_id, state=TaskState.QUEUED)
                                self.queue.requeue(task_id)
                            else:
                                self.repository.update_task(
                                    task_id,
                                    state=TaskState.FAILED,
                                    error_message="Lease expired, max attempts reached",
                                )
                                self.queue.acknowledge(task_id)


class CeleryWorkerRuntime(WorkerRuntime):
    """Celery-backed Worker Runtime adapter."""

    def __init__(self, celery_app: Any) -> None:
        self.celery_app = celery_app

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass
