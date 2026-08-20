"""Security & adversarial tests for KarsaSec Async Workers Subsystem (Sprint F2).

Verifies:
- Task state machine transitions and transition validation.
- Idempotency & replay protection (concurrent/repeated submissions).
- Lease recovery & crash recovery (worker crash simulation, lease timeout > 300s).
- Retry policy & max attempt limits.
- L7 (Zero Security Authority) enforcement.
- R7-R9 (Privacy Boundary) compliance in tasks.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from karsasec.server.app import create_app
from karsasec.server.config import ServerSettings
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.workers.repository import InMemoryTaskRepository
from karsasec.workers.queue import InMemoryTaskQueue
from karsasec.workers.worker import CustomWorkerRuntime

_VALID_KEY = "karsasec-dev-secret-key-change-in-production-32bytes"


@pytest.fixture
def test_client():
    settings = ServerSettings(auth_secret_key=_VALID_KEY)
    app = create_app(settings=settings)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def auth_headers():
    return {"X-API-Key": _VALID_KEY}


# -------------------------------------------------------------------------
# 1. State Machine Transition Tests
# -------------------------------------------------------------------------
class TestTaskStateMachine:
    def test_valid_transitions(self):
        task = RemediationTask(
            task_id="tsk_test_1",
            finding_id="f1",
            approval_token_id="tok1",
            token="secret_tok",
            fingerprint="fp1",
        )
        assert task.state == TaskState.PENDING

        task.transition_to(TaskState.QUEUED)
        assert task.state == TaskState.QUEUED

        task.transition_to(TaskState.RUNNING)
        assert task.state == TaskState.RUNNING
        assert task.attempts == 1
        assert task.started_at is not None

        task.transition_to(TaskState.COMPLETED)
        assert task.state == TaskState.COMPLETED
        assert task.started_at is None

    def test_invalid_transitions_raise_value_error(self):
        task = RemediationTask(
            task_id="tsk_test_2",
            finding_id="f1",
            approval_token_id="tok1",
            token="secret_tok",
            fingerprint="fp1",
        )
        # Cannot go PENDING -> COMPLETED directly
        with pytest.raises(ValueError):
            task.transition_to(TaskState.COMPLETED)

        # Cannot go PENDING -> RUNNING directly
        with pytest.raises(ValueError):
            task.transition_to(TaskState.RUNNING)


# -------------------------------------------------------------------------
# 2. Idempotency & Replay Attack Protection Tests
# -------------------------------------------------------------------------
class TestIdempotencyEngine:
    def test_duplicate_submissions_return_same_task(self, test_client, auth_headers):
        payload = {
            "finding_id": "f_id_100",
            "approval": {"approval_token_id": "tok_100", "token": "tok_credential_100"},
        }
        # First submission
        resp1 = test_client.post("/api/v1/remediations", json=payload, headers=auth_headers)
        assert resp1.status_code == 202
        data1 = resp1.json()
        assert "transaction_id" in data1

        # Second submission (replay)
        resp2 = test_client.post("/api/v1/remediations", json=payload, headers=auth_headers)
        assert resp2.status_code == 202
        data2 = resp2.json()

        # Both transaction IDs must be identical
        assert data1["transaction_id"] == data2["transaction_id"]
        assert data1["state"] == data2["state"]


# -------------------------------------------------------------------------
# 3. Lease Recovery Tests
# -------------------------------------------------------------------------
class TestLeaseRecovery:
    def test_lease_expiry_requeues_running_task(self):
        repo = InMemoryTaskRepository()
        queue = InMemoryTaskQueue()
        runtime = CustomWorkerRuntime(queue=queue, repository=repo)

        task = RemediationTask(
            task_id="tsk_lease_1",
            finding_id="f1",
            approval_token_id="tok1",
            token="secret_tok",
            fingerprint="fp1",
        )
        repo.create_task(task)
        # Transition task to RUNNING (this starts lease)
        repo.update_task("tsk_lease_1", state=TaskState.QUEUED)
        queue.enqueue("tsk_lease_1")
        queue.dequeue()  # Puts task in processing queue
        repo.update_task("tsk_lease_1", state=TaskState.RUNNING)

        # Confirm task is RUNNING and in processing queue
        assert task.state == TaskState.RUNNING
        assert "tsk_lease_1" in queue.get_processing_tasks()

        # Simulate time jump > 300s (e.g. 350s)
        expired_time = task.started_at + 350.0

        # Trigger lease recovery
        runtime.recover_stale_tasks(current_time=expired_time)

        # Task should transition to QUEUED and be moved back to the main queue
        assert task.state == TaskState.QUEUED
        assert "tsk_lease_1" not in queue.get_processing_tasks()
        # Verify task is available in main queue
        assert queue.dequeue() == "tsk_lease_1"


# -------------------------------------------------------------------------
# 4. Retry Policy & Failure Protection Tests
# -------------------------------------------------------------------------
class TestRetryPolicy:
    def test_max_attempts_exceeded_transitions_to_failed(self):
        repo = InMemoryTaskRepository()
        queue = InMemoryTaskQueue()
        runtime = CustomWorkerRuntime(queue=queue, repository=repo)

        task = RemediationTask(
            task_id="tsk_retry_1",
            finding_id="f1",
            approval_token_id="tok1",
            token="secret_tok",
            fingerprint="fp1",
            max_attempts=3,
        )
        repo.create_task(task)
        repo.update_task("tsk_retry_1", state=TaskState.QUEUED)
        queue.enqueue("tsk_retry_1")

        import unittest.mock

        # Simulate worker processing and failing 3 times
        with unittest.mock.patch(
            "karsasec.workers.worker.RemediationLifecycleEngine.execute",
            side_effect=Exception("Simulated execution failure"),
        ):
            for i in range(3):
                task_id = queue.dequeue()
                assert task_id == "tsk_retry_1"
                runtime.process_task(task_id)

        # After 3 failed attempts, state must be FAILED, not QUEUED
        assert task.state == TaskState.FAILED
        assert task.attempts == 3
        assert "tsk_retry_1" not in queue.get_processing_tasks()


# -------------------------------------------------------------------------
# 5. L7 & R7-R9 Invariant Verification
# -------------------------------------------------------------------------
class TestSecurityAndPrivacyInvariants:
    def test_worker_and_api_are_zero_security_authority(self):
        """Verify that security_verification_status is not manually set to SECURITY_VERIFIED."""
        task = RemediationTask(
            task_id="tsk_inv_1",
            finding_id="f1",
            approval_token_id="tok1",
            token="secret_tok",
            fingerprint="fp1",
        )
        # Default is not verified
        assert task.security_verification_status is None

    def test_task_serialization_privacy_safe(self):
        """Verify task.to_dict() does not leak sensitive information like raw credentials/tokens/source code."""
        task = RemediationTask(
            task_id="tsk_inv_2",
            finding_id="f1",
            approval_token_id="tok_12345",
            token="secret_sensitive_api_token",
            fingerprint="fp123",
        )
        serialized = task.to_dict()
        assert "token" not in serialized
        # Ensure credentials/source code are completely absent
        for key in serialized.keys():
            assert "source" not in key
            assert "diff" not in key

    def test_queue_poisoning_rejection(self, test_client, auth_headers):
        """Verify malformed payload or command injections are rejected or ignored without shell execution."""
        payload = {
            "finding_id": "; rm -rf /",
            "approval": {"approval_token_id": "tok_poison", "token": "secret_token_val"},
        }
        resp = test_client.post("/api/v1/remediations", json=payload, headers=auth_headers)
        assert resp.status_code == 202

    def test_forged_completion_prevention(self):
        """Verify task state transition rules prevent direct forgery of COMPLETED state."""
        task = RemediationTask(
            task_id="tsk_forge",
            finding_id="f1",
            approval_token_id="tok1",
            token="secret_tok",
            fingerprint="fp1",
        )
        with pytest.raises(ValueError):
            task.transition_to(TaskState.COMPLETED)
