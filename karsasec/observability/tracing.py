"""TraceContext & TraceManager — Privacy-Safe Distributed Tracing for Sprint F4.

Propagates trace correlation context across REST API requests, background task queues,
and persistence audit logs.

Invariants:
  - R7-R9: Privacy Boundary — no source code, diffs, credentials, or tokens in trace attributes.
"""

from __future__ import annotations

import hmac
import hashlib
import uuid


def canonicalize_trace_fields(
    parent_hash: str | None,
    trace_id: str,
    span_id: str,
    correlation_id: str,
) -> bytes:
    """Canonical deterministic field serialization helper for trace hash computation (INV-07)."""
    p_hash = parent_hash or "ROOT"
    canonical_str = f"parent_hash={p_hash}&trace_id={trace_id}&span_id={span_id}&correlation_id={correlation_id}"
    return canonical_str.encode("utf-8")


class TraceContext:
    """Immutable trace propagation context with tamper-detection hash chaining.

    THREAT MODEL & SECURITY BOUNDARY (INV-06):
    -----------------------------------------
    - SHA-256 Trace Hash (`X-Trace-Hash`): Mandatory structural tamper-detection & correlation integrity mechanism.
      Protects against accidental corruption or unauthorized span manipulation in transit.
      LIMITATION: SHA-256 does NOT provide sender authenticity or non-repudiation because any caller can compute SHA-256.
    - HMAC-SHA256 Signature (`X-Trace-Signature`): Optional authenticated deployment mode when an `hmac_key`
      is configured. Proves sender authenticity without hardcoding secrets.
    """

    __slots__ = ("trace_id", "span_id", "correlation_id", "parent_span_id", "parent_hash", "trace_hash")

    def __init__(
        self,
        trace_id: str | None = None,
        span_id: str | None = None,
        correlation_id: str | None = None,
        parent_span_id: str | None = None,
        parent_hash: str | None = None,
        trace_hash: str | None = None,
    ) -> None:
        self.trace_id = trace_id or f"trc_{uuid.uuid4().hex[:16]}"
        self.span_id = span_id or f"spn_{uuid.uuid4().hex[:12]}"
        self.correlation_id = correlation_id or self.trace_id
        self.parent_span_id = parent_span_id
        self.parent_hash = parent_hash

        # Compute deterministic canonical trace hash (INV-07)
        if trace_hash is not None:
            self.trace_hash = trace_hash
        else:
            self.trace_hash = self.compute_canonical_hash(
                self.parent_hash, self.trace_id, self.span_id, self.correlation_id
            )

    @staticmethod
    def compute_canonical_hash(
        parent_hash: str | None,
        trace_id: str,
        span_id: str,
        correlation_id: str,
    ) -> str:
        """Compute SHA-256 digest over canonical field serialization."""
        payload = canonicalize_trace_fields(parent_hash, trace_id, span_id, correlation_id)
        return hashlib.sha256(payload).hexdigest()

    def validate_integrity(self, expected_parent_hash: str | None = None) -> bool:
        """Validate if self.trace_hash matches canonical hash over active fields (INV-08).

        Returns False if trace_id, span_id, correlation_id, parent_hash, or trace_hash was tampered with.
        """
        p_hash = expected_parent_hash if expected_parent_hash is not None else self.parent_hash
        expected_hash = self.compute_canonical_hash(p_hash, self.trace_id, self.span_id, self.correlation_id)
        return hmac.compare_digest(self.trace_hash, expected_hash)

    def compute_hmac_signature(self, secret_key: bytes) -> str:
        """Compute HMAC-SHA256 signature for authenticated deployment mode."""
        payload = canonicalize_trace_fields(self.parent_hash, self.trace_id, self.span_id, self.correlation_id)
        return hmac.new(secret_key, payload, hashlib.sha256).hexdigest()

    def validate_hmac_signature(self, signature: str, secret_key: bytes) -> bool:
        """Verify HMAC-SHA256 signature using constant-time comparison."""
        expected = self.compute_hmac_signature(secret_key)
        return hmac.compare_digest(signature, expected)

    def new_child_span(self) -> TraceContext:
        """Create a child span sharing the same trace_id and correlation_id with chained hash."""
        return TraceContext(
            trace_id=self.trace_id,
            span_id=f"spn_{uuid.uuid4().hex[:12]}",
            correlation_id=self.correlation_id,
            parent_span_id=self.span_id,
            parent_hash=self.trace_hash,
        )

    def to_headers(self, secret_key: bytes | None = None) -> dict[str, str]:
        """Format as HTTP propagation headers including trace hash and optional HMAC signature."""
        headers = {
            "X-Trace-ID": self.trace_id,
            "X-Span-ID": self.span_id,
            "X-Correlation-ID": self.correlation_id,
            "X-Trace-Hash": self.trace_hash,
        }
        if secret_key:
            headers["X-Trace-Signature"] = self.compute_hmac_signature(secret_key)
        return headers

    @classmethod
    def from_headers(cls, headers: dict[str, str]) -> TraceContext:
        """Extract trace context from HTTP headers."""
        trace_id = headers.get("X-Trace-ID") or headers.get("x-trace-id")
        span_id = headers.get("X-Span-ID") or headers.get("x-span-id")
        correlation_id = (
            headers.get("X-Correlation-ID")
            or headers.get("x-correlation-id")
            or headers.get("X-Request-ID")
            or headers.get("x-request-id")
        )
        trace_hash = headers.get("X-Trace-Hash") or headers.get("x-trace-hash")
        return cls(trace_id=trace_id, span_id=span_id, correlation_id=correlation_id, trace_hash=trace_hash)


class TraceManager:
    """Manager for managing current trace context per thread or task scope."""

    def __init__(self) -> None:
        self._current: TraceContext | None = None

    def start_trace(self, correlation_id: str | None = None) -> TraceContext:
        self._current = TraceContext(correlation_id=correlation_id)
        return self._current

    def get_current(self) -> TraceContext:
        if self._current is None:
            self._current = TraceContext()
        return self._current

    def set_current(self, context: TraceContext) -> None:
        self._current = context
