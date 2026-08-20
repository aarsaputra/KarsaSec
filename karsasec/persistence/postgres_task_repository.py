import uuid
from typing import List, Optional, Any
from sqlalchemy import update, select
from sqlalchemy.orm import Session

from karsasec.persistence.db import DatabaseSessionFactory, get_session_factory
from karsasec.persistence.models import TaskModel, WorkerModel, DeadLetterEventModel
from karsasec.events.audit_ledger import TaskAuditLedger
from karsasec.events.outbox import TransactionalOutbox
from karsasec.workers.repository import TaskRepository
from karsasec.workers.task import (
    RemediationTask,
    TaskState,
    StaleLeaseVersionError,
    InvalidTaskStateError,
    WorkerFencedError,
    InvalidWorkerStateError,
)


class PostgresTaskRepository(TaskRepository):
    """Authoritative PostgreSQL Task Repository enforcing atomic CAS & fencing version invariants."""

    def __init__(
        self,
        session_factory: DatabaseSessionFactory | None = None,
        factory: DatabaseSessionFactory | None = None,
        audit_repo: Any = None,
        metrics_registry: Any = None,
        **kwargs: Any,
    ) -> None:
        self._session_factory = session_factory or factory or get_session_factory()
        self._audit_repo = audit_repo
        self._metrics_registry = metrics_registry

    def _append_audit(self, event_type: str, task_id: str, details: dict[str, Any]) -> None:
        if self._audit_repo:
            try:
                from karsasec.persistence.audit_repository import AuditEvent
                self._audit_repo.append(AuditEvent(
                    task_id=task_id,
                    event_type=event_type,
                    details=details,
                ))
            except Exception:
                pass

    def _model_to_domain(self, model: TaskModel) -> RemediationTask:
        """Map TaskModel ORM object to domain RemediationTask."""
        state = TaskState(model.state)
        task = RemediationTask(
            task_id=model.task_id,
            finding_id=model.finding_id,
            approval_token_id=model.approval_token_id,
            token="",  # Token is not persisted for privacy
            fingerprint=model.fingerprint,
            state=state,
            attempts=model.attempts,
            max_attempts=model.max_attempts,
            lease_seconds=model.lease_seconds,
        )
        task.lease_version = model.lease_version
        task.error_message = model.error_message
        task.receipt_id = model.receipt_id
        task.receipt_fingerprint = model.receipt_fingerprint
        task.security_verification_status = model.security_verification_status
        return task

    def create_task(self, task: RemediationTask) -> None:
        """Saves a new task to PostgreSQL persistence and stages genesis audit/outbox events."""
        with self._session_factory.session_scope() as session:
            existing = session.scalar(select(TaskModel).where(TaskModel.task_id == task.task_id))
            if existing:
                raise ValueError(f"Task with ID {task.task_id} already exists")

            state_str = task.state.value if isinstance(task.state, TaskState) else str(task.state)
            model = TaskModel(
                task_id=task.task_id,
                finding_id=task.finding_id,
                approval_token_id=task.approval_token_id,
                fingerprint=task.fingerprint,
                state=state_str,
                attempts=task.attempts,
                max_attempts=task.max_attempts,
                lease_seconds=task.lease_seconds,
                lease_version=task.lease_version,
                error_message=task.error_message,
                receipt_id=task.receipt_id,
                receipt_fingerprint=task.receipt_fingerprint,
                security_verification_status=task.security_verification_status,
            )
            session.add(model)
            session.flush()

            # Automatic Audit and Outbox Staging
            TaskAuditLedger.record_transition(
                session,
                task_id=task.task_id,
                previous_state="NONE",
                new_state=state_str,
                lease_version=task.lease_version,
                reason="TASK_CREATED",
            )
            TransactionalOutbox.stage_event(
                session,
                aggregate_type="remediation_task",
                aggregate_id=task.task_id,
                event_type="TASK_CREATED",
                payload={"task_id": task.task_id, "state": state_str},
                lease_version=task.lease_version,
                deduplication_key=f"task_created_{task.task_id}",
            )

    def get_task(self, task_id: str) -> Optional[RemediationTask]:
        """Retrieves a task by ID from PostgreSQL."""
        session = self._session_factory.get_session()
        try:
            model = session.scalar(select(TaskModel).where(TaskModel.task_id == task_id))
            if not model:
                return None
            return self._model_to_domain(model)
        finally:
            session.close()

    def update_task(self, task_id: str, **kwargs) -> RemediationTask:
        """Updates task fields atomically in PostgreSQL."""
        if "state" in kwargs:
            new_state = kwargs.pop("state")
            new_state_obj = TaskState(new_state) if isinstance(new_state, str) else new_state
            current = self.get_task(task_id)
            if not current:
                raise ValueError(f"Task with ID {task_id} not found")
            return self.atomic_transition(
                task_id=task_id,
                expected_lease_version=current.lease_version,
                expected_states=[current.state],
                new_state=new_state_obj,
                **kwargs,
            )

        with self._session_factory.session_scope() as session:
            model = session.scalar(select(TaskModel).where(TaskModel.task_id == task_id).with_for_update())
            if not model:
                raise ValueError(f"Task with ID {task_id} not found")

            for key, val in kwargs.items():
                if hasattr(model, key):
                    setattr(model, key, val)
                else:
                    raise AttributeError(f"TaskModel has no attribute '{key}'")
            session.flush()
            return self._model_to_domain(model)

    def atomic_transition(
        self,
        task_id: str,
        expected_lease_version: int,
        expected_states: List[TaskState],
        new_state: TaskState,
        **kwargs,
    ) -> RemediationTask:
        """Atomically validates lease_version & state via single SQL UPDATE statement (INV-F5-02)."""
        expected_state_strs = [
            s.value if isinstance(s, TaskState) else str(s) for s in expected_states
        ]
        target_state_str = new_state.value if isinstance(new_state, TaskState) else str(new_state)

        next_lease_version = kwargs.get("lease_version", expected_lease_version + 1)

        # Terminal state resurrection check (INV-F5-08)
        terminal_states = {TaskState.COMPLETED.value, TaskState.FAILED.value, TaskState.CANCELLED.value}
        if target_state_str in {TaskState.QUEUED.value, TaskState.RUNNING.value}:
            if any(s in terminal_states for s in expected_state_strs):
                raise InvalidTaskStateError(
                    f"Terminal state task '{task_id}' cannot be resurrected to '{target_state_str}'."
                )

        update_values: dict[str, Any] = {
            "state": target_state_str,
            "lease_version": next_lease_version,
        }

        if "error_message" in kwargs:
            update_values["error_message"] = kwargs["error_message"]
        if "assigned_worker_id" in kwargs:
            update_values["assigned_worker_id"] = kwargs["assigned_worker_id"]
        if "recovery_fencing_token" in kwargs:
            update_values["recovery_fencing_token"] = kwargs["recovery_fencing_token"]
        if target_state_str == TaskState.RUNNING.value:
            # Increment attempts on transition to RUNNING
            update_values["attempts"] = TaskModel.attempts + 1

        stale_lease_error = None
        invalid_state_error = None
        result_domain = None

        with self._session_factory.session_scope() as session:
            stmt = (
                update(TaskModel)
                .where(
                    TaskModel.task_id == task_id,
                    TaskModel.lease_version == expected_lease_version,
                    TaskModel.state.in_(expected_state_strs),
                )
                .values(**update_values)
            )

            result = session.execute(stmt)
            if getattr(result, "rowcount", 0) == 1:
                session.flush()
                model = session.scalar(select(TaskModel).where(TaskModel.task_id == task_id))
                if not model:
                    raise ValueError(f"Task with ID '{task_id}' not found after update")

                TaskAuditLedger.record_transition(
                    session,
                    task_id=task_id,
                    previous_state=expected_state_strs[0] if expected_state_strs else "UNKNOWN",
                    new_state=target_state_str,
                    worker_id=kwargs.get("assigned_worker_id"),
                    fencing_token=kwargs.get("recovery_fencing_token"),
                    lease_version=next_lease_version,
                    reason=kwargs.get("reason", "ATOMIC_TRANSITION"),
                )
                TransactionalOutbox.stage_event(
                    session,
                    aggregate_type="remediation_task",
                    aggregate_id=task_id,
                    event_type=f"TASK_{target_state_str}",
                    payload={"task_id": task_id, "state": target_state_str},
                    lease_version=next_lease_version,
                    deduplication_key=f"task_transition_{task_id}_{next_lease_version}",
                )
                result_domain = self._model_to_domain(model)

            else:
                # Zero rows updated — analyze cause for authoritative domain exception
                current_model = session.scalar(select(TaskModel).where(TaskModel.task_id == task_id))
                if not current_model:
                    raise ValueError(f"Task with ID '{task_id}' not found")

                # Check terminal state resurrection guard
                if current_model.state in terminal_states:
                    invalid_state_error = InvalidTaskStateError(
                        f"Terminal state task '{task_id}' (state='{current_model.state}') cannot be resurrected to '{target_state_str}'."
                    )
                elif current_model.lease_version != expected_lease_version:
                    stale_lease_error = (
                        StaleLeaseVersionError(
                            f"Task fencing lease version mismatch for '{task_id}'. Expected v{expected_lease_version}, active is v{current_model.lease_version}."
                        ),
                        current_model.lease_version,
                    )
                elif current_model.state not in expected_state_strs:
                    invalid_state_error = InvalidTaskStateError(
                        f"Task state transition rejected for '{task_id}'. Current state '{current_model.state}' not in expected {expected_state_strs}."
                    )
                else:
                    invalid_state_error = InvalidTaskStateError(
                        f"Atomic state transition failed for task '{task_id}'."
                    )

        if result_domain:
            self._append_audit(
                "TASK_STATE_CHANGED",
                task_id,
                {
                    "previous_state": expected_state_strs[0] if expected_state_strs else "UNKNOWN",
                    "new_state": target_state_str,
                    "lease_version": next_lease_version,
                },
            )
            return result_domain

        if stale_lease_error:
            err, active_ver = stale_lease_error
            self._append_audit(
                "TASK_CAS_REJECTED",
                task_id,
                {
                    "expected_lease_version": expected_lease_version,
                    "active_lease_version": active_ver,
                    "reason": "STALE_LEASE_VERSION",
                },
            )
            raise err

        if invalid_state_error:
            raise invalid_state_error

    def assign_task(self, task_id: str, worker_id: str) -> RemediationTask:
        """Assigns a task to an online worker and transitions state from QUEUED/PENDING to RUNNING."""
        with self._session_factory.session_scope() as session:
            worker = session.scalar(select(WorkerModel).where(WorkerModel.worker_id == worker_id))
            if worker and worker.status in ("DRAINING", "DRAINED", "FENCED", "OFFLINE"):
                raise InvalidWorkerStateError(
                    f"Worker '{worker_id}' status is '{worker.status}', expected ONLINE for assignment."
                )

            worker_fencing_token = worker.fencing_token if worker else 1

            model = session.scalar(select(TaskModel).where(TaskModel.task_id == task_id).with_for_update())
            if not model:
                raise ValueError(f"Task with ID '{task_id}' not found")

            terminal_states = {TaskState.COMPLETED.value, TaskState.FAILED.value, TaskState.CANCELLED.value}
            if model.state in terminal_states:
                raise InvalidTaskStateError(f"Terminal state task '{task_id}' cannot be assigned.")

            if model.attempts >= model.max_attempts:
                raise InvalidTaskStateError(f"Task '{task_id}' attempts exhausted ({model.attempts}/{model.max_attempts}).")

            if model.state not in (TaskState.QUEUED.value, TaskState.PENDING.value):
                raise InvalidTaskStateError(
                    f"Task state transition rejected for '{task_id}'. Current state '{model.state}' not in expected QUEUED/PENDING."
                )

            prev_state = model.state
            model.state = TaskState.RUNNING.value
            model.assigned_worker_id = worker_id
            model.assigned_worker_fencing_token = worker_fencing_token
            model.attempts = model.attempts + 1
            model.lease_version = model.lease_version + 1

            session.flush()

            TaskAuditLedger.record_transition(
                session,
                task_id=task_id,
                previous_state=prev_state,
                new_state=TaskState.RUNNING.value,
                worker_id=worker_id,
                fencing_token=worker_fencing_token,
                lease_version=model.lease_version,
                reason="TASK_ASSIGNED",
            )
            TransactionalOutbox.stage_event(
                session,
                aggregate_type="remediation_task",
                aggregate_id=task_id,
                event_type="TASK_ASSIGNED",
                payload={"task_id": task_id, "worker_id": worker_id, "state": "RUNNING"},
                lease_version=model.lease_version,
                deduplication_key=f"task_assigned_{task_id}_{model.lease_version}",
            )

            return self._model_to_domain(model)

    def complete_task(
        self,
        task_id: str,
        expected_lease_version: int,
        worker_id: str,
        worker_fencing_token: int = 1,
        receipt_id: str | None = None,
        receipt_fingerprint: str | None = None,
        security_verification_status: str | None = None,
    ) -> RemediationTask:
        """Atomically completes a RUNNING task."""
        with self._session_factory.session_scope() as session:
            worker = session.scalar(select(WorkerModel).where(WorkerModel.worker_id == worker_id))
            if worker:
                if worker.status in ("FENCED", "OFFLINE"):
                    raise WorkerFencedError(
                        f"Worker '{worker_id}' status is '{worker.status}' and cannot mutate task '{task_id}'."
                    )
                if worker.fencing_token > worker_fencing_token:
                    raise WorkerFencedError(
                        f"Worker '{worker_id}' fencing token mismatch (active {worker.fencing_token} > provided {worker_fencing_token})."
                    )

            model = session.scalar(select(TaskModel).where(TaskModel.task_id == task_id).with_for_update())
            if not model:
                raise ValueError(f"Task with ID '{task_id}' not found")

            if model.assigned_worker_id and model.assigned_worker_id != worker_id:
                raise WorkerFencedError(
                    f"Worker '{worker_id}' cannot mutate task '{task_id}' assigned to '{model.assigned_worker_id}'."
                )

            if model.lease_version != expected_lease_version:
                raise StaleLeaseVersionError(
                    f"Task fencing lease version mismatch for '{task_id}'. Expected v{expected_lease_version}, active is v{model.lease_version}."
                )

            if model.state != TaskState.RUNNING.value:
                raise InvalidTaskStateError(
                    f"Task state '{model.state}' cannot be completed."
                )

            prev_state = model.state
            model.state = TaskState.COMPLETED.value
            model.lease_version = expected_lease_version + 1
            if receipt_id:
                model.receipt_id = receipt_id
            if receipt_fingerprint:
                model.receipt_fingerprint = receipt_fingerprint
            if security_verification_status:
                model.security_verification_status = security_verification_status

            session.flush()

            TaskAuditLedger.record_transition(
                session,
                task_id=task_id,
                previous_state=prev_state,
                new_state=TaskState.COMPLETED.value,
                worker_id=worker_id,
                fencing_token=worker_fencing_token,
                lease_version=model.lease_version,
                reason="TASK_COMPLETED",
            )
            TransactionalOutbox.stage_event(
                session,
                aggregate_type="remediation_task",
                aggregate_id=task_id,
                event_type="TASK_COMPLETED",
                payload={"task_id": task_id, "worker_id": worker_id, "state": "COMPLETED"},
                lease_version=model.lease_version,
                deduplication_key=f"task_completed_{task_id}_{model.lease_version}",
            )

            return self._model_to_domain(model)

    def record_execution_failure(
        self,
        task_id: str,
        expected_lease_version: int,
        worker_id: str,
        worker_fencing_token: int = 1,
        error_message: str = "",
    ) -> RemediationTask:
        """Records execution failure, requeuing or DLQ-exhausting task."""
        with self._session_factory.session_scope() as session:
            worker = session.scalar(select(WorkerModel).where(WorkerModel.worker_id == worker_id))
            if worker:
                if worker.status in ("FENCED", "OFFLINE"):
                    raise WorkerFencedError(
                        f"Worker '{worker_id}' status is '{worker.status}' and cannot mutate task '{task_id}'."
                    )
                if worker.fencing_token > worker_fencing_token:
                    raise WorkerFencedError(
                        f"Worker '{worker_id}' fencing token mismatch (active {worker.fencing_token} > provided {worker_fencing_token})."
                    )

            model = session.scalar(select(TaskModel).where(TaskModel.task_id == task_id).with_for_update())
            if not model:
                raise ValueError(f"Task with ID '{task_id}' not found")

            if model.assigned_worker_id and model.assigned_worker_id != worker_id:
                raise WorkerFencedError(
                    f"Worker '{worker_id}' cannot mutate task '{task_id}' assigned to '{model.assigned_worker_id}'."
                )

            if model.lease_version != expected_lease_version:
                raise StaleLeaseVersionError(
                    f"Task fencing lease version mismatch for '{task_id}'. Expected v{expected_lease_version}, active is v{model.lease_version}."
                )

            if model.state != TaskState.RUNNING.value:
                raise InvalidTaskStateError(
                    f"Task state '{model.state}' cannot record execution failure."
                )

            prev_state = model.state
            model.lease_version = expected_lease_version + 1
            model.error_message = error_message

            if model.attempts >= model.max_attempts:
                # Exhausted -> FAILED state
                model.state = TaskState.FAILED.value
                dlq = DeadLetterEventModel(
                    event_id=f"dlq_{uuid.uuid4().hex[:16]}",
                    task_id=task_id,
                    reason="EXHAUSTED",
                    attempts=model.attempts,
                    max_attempts=model.max_attempts,
                    sanitized_error_message=error_message[:8192],
                    worker_id=worker_id,
                )
                session.add(dlq)
                session.flush()

                TaskAuditLedger.record_transition(
                    session,
                    task_id=task_id,
                    previous_state=prev_state,
                    new_state=TaskState.FAILED.value,
                    worker_id=worker_id,
                    fencing_token=worker_fencing_token,
                    lease_version=model.lease_version,
                    reason="TASK_FAILED",
                )
                TransactionalOutbox.stage_event(
                    session,
                    aggregate_type="remediation_task",
                    aggregate_id=task_id,
                    event_type="TASK_FAILED",
                    payload={"task_id": task_id, "worker_id": worker_id, "state": "FAILED"},
                    lease_version=model.lease_version,
                    deduplication_key=f"task_failure_{task_id}_{model.lease_version}",
                )
            else:
                # Retryable -> QUEUED state
                model.state = TaskState.QUEUED.value
                model.assigned_worker_id = None
                model.assigned_worker_fencing_token = None
                session.flush()

                TaskAuditLedger.record_transition(
                    session,
                    task_id=task_id,
                    previous_state=prev_state,
                    new_state=TaskState.QUEUED.value,
                    worker_id=worker_id,
                    fencing_token=worker_fencing_token,
                    lease_version=model.lease_version,
                    reason="TASK_RETRIED",
                )
                TransactionalOutbox.stage_event(
                    session,
                    aggregate_type="remediation_task",
                    aggregate_id=task_id,
                    event_type="TASK_RETRIED",
                    payload={"task_id": task_id, "worker_id": worker_id, "state": "QUEUED"},
                    lease_version=model.lease_version,
                    deduplication_key=f"task_transition_{task_id}_{model.lease_version}",
                )

            return self._model_to_domain(model)

    def get_active_task_by_fingerprint(self, fingerprint: str) -> Optional[RemediationTask]:
        """Finds any non-terminal task matching the fingerprint."""
        terminal_states = [
            TaskState.COMPLETED.value,
            TaskState.FAILED.value,
            TaskState.CANCELLED.value,
        ]
        session = self._session_factory.get_session()
        try:
            model = session.scalar(
                select(TaskModel).where(
                    TaskModel.fingerprint == fingerprint,
                    ~TaskModel.state.in_(terminal_states),
                )
            )
            if not model:
                return None
            return self._model_to_domain(model)
        finally:
            session.close()

    def list_tasks(
        self, states: Optional[list[TaskState]] = None, limit: int = 100
    ) -> list[RemediationTask]:
        """List tasks optionally filtered by state."""
        session = self._session_factory.get_session()
        try:
            query = select(TaskModel)
            if states:
                state_strs = [s.value if isinstance(s, TaskState) else str(s) for s in states]
                query = query.where(TaskModel.state.in_(state_strs))
            query = query.limit(limit)

            models = session.scalars(query).all()
            return [self._model_to_domain(m) for m in models]
        finally:
            session.close()
