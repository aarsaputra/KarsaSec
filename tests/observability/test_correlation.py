"""Unit tests for ContextVar Correlation Propagation (Sprint F6A)."""

from __future__ import annotations

import concurrent.futures
import asyncio
import pytest

from karsasec.observability.correlation import (
    correlation_scope,
    get_correlation_id,
    get_request_id,
    get_operation_id,
    set_correlation_id,
)


class TestCorrelationContext:
    def test_correlation_scope_sets_and_resets(self):
        assert get_correlation_id() is None
        with correlation_scope("corr-fixed-123", request_id="req-1", operation_id="op-1") as cid:
            assert cid == "corr-fixed-123"
            assert get_correlation_id() == "corr-fixed-123"
            assert get_request_id() == "req-1"
            assert get_operation_id() == "op-1"
        assert get_correlation_id() is None

    def test_thread_pool_correlation_isolation(self):
        set_correlation_id("parent-corr-id")

        results = {}

        def worker_task(worker_name: str, cid_val: str):
            with correlation_scope(cid_val):
                results[worker_name] = get_correlation_id()

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            f1 = executor.submit(worker_task, "w1", "corr-worker-1")
            f2 = executor.submit(worker_task, "w2", "corr-worker-2")
            concurrent.futures.wait([f1, f2])

        assert results["w1"] == "corr-worker-1"
        assert results["w2"] == "corr-worker-2"
        assert get_correlation_id() == "parent-corr-id"

    @pytest.mark.asyncio
    async def test_async_task_correlation_inheritance(self):
        with correlation_scope("async-corr-100"):
            assert get_correlation_id() == "async-corr-100"

            async def sub_task():
                return get_correlation_id()

            res = await asyncio.create_task(sub_task())
            assert res == "async-corr-100"
