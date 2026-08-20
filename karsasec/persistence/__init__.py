"""KarsaSec Persistence Layer (Sprint F3).

Provides production-grade PostgreSQL persistence for tasks, receipts, and audit events.
Enforces:
  - L7: Zero LLM / Worker Security Authority.
  - R7-R9: Privacy Boundary (no source code, diffs, credentials in DB).
  - Determinism: Ordered queries, no insertion-order dependence.
"""
