# ADR F4 — Distributed Cluster Coordination & Observability

## Context & Problem Statement
As KarsaSec scales horizontally across multiple worker nodes, single-node task dispatching and uncoordinated recovery cause potential worker impersonation, split-brain recovery, and observability gaps. A distributed coordination framework is required.

## Architectural Decisions

1. **Token-Authenticated Worker Registry**:
   - Workers must register with SHA-256 token hashing.
   - Forged heartbeats from unregistered or improperly authenticated workers trigger `FORGED_WORKER_HEARTBEAT` audit events.

2. **Deterministic Round Robin Scheduler (v1)**:
   - Worker selection follows deterministic formula $\text{index} = \text{task\_counter} \pmod{|\text{active\_workers}|}$.
   - Evaluates only `ONLINE` and `DEGRADED` worker nodes.

3. **Cluster Dead-Worker Recovery**:
   - Startup and background recovery scans for `RUNNING` tasks assigned to `OFFLINE` workers (>90s heartbeat gap).
   - Requeues tasks safely while preserving terminal states (`COMPLETED`, `FAILED`, `CANCELLED`).

4. **Privacy-Guarded Prometheus Exporter**:
   - Standard `/metrics` endpoint exposes scalar telemetry counters and gauges.
   - Enforces R7-R9 Privacy Boundary: Zero source code, diffs, tokens, credentials, or API keys permitted in metric payloads.

## Status
**ACCEPTED**
