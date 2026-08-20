# Phase 1 — Sprint F4 Repository Dependency Analysis

## Overview
This document outlines the dependency graph, module layout, and structural relationships for `karsasec/observability/` and distributed worker coordination components in `karsasec/workers/`.

## File Structure Map
```text
karsasec/
├── observability/
│   ├── __init__.py
│   ├── metrics.py
│   ├── tracing.py
│   ├── health.py
│   ├── dashboard.py
│   └── prometheus_exporter.py
└── workers/
    ├── worker_registry.py
    ├── heartbeat.py
    ├── scheduler.py
    └── cluster_recovery.py
```

## Module Dependency Graph

```mermaid
graph TD
    subgraph Observability Module
        Metrics[observability.metrics]
        Tracing[observability.tracing]
        Health[observability.health]
        Exporter[observability.prometheus_exporter]
        Dashboard[observability.dashboard]
    end

    subgraph Workers Coordination Module
        Registry[workers.worker_registry]
        Heartbeat[workers.heartbeat]
        Scheduler[workers.scheduler]
        Recovery[workers.cluster_recovery]
    end

    Exporter -->|scrapes| Metrics
    Dashboard -->|reads| Metrics
    Dashboard -->|reads| Health

    Heartbeat -->|evaluates| Registry
    Scheduler -->|queries active| Registry
    Recovery -->|queries offline| Registry
    Recovery -->|inc recovery count| Metrics
```
