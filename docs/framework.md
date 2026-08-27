# KarsaSec Framework Semantic Layer Architecture

## Overview

Sprint E10-1 memperkenalkan **Framework Semantic Layer** sebagai layer abstraksi di atas Code Property Graph (CPG). Layer ini memetakan framework Web/API spesifik (Flask, Django, FastAPI, Express, Next.js, Laravel, Gin) ke dalam skema semantik terstandarisasi.

---

## Core Components

```
Project Files / AST / Manifests
            │
            ▼
   FrameworkDetector ── (Weighted Confidence Scoring: Manifest 0.6, Import 0.9, Call 1.0)
            │
            ├── FrameworkResolver (Import Aliases)
            ├── FrameworkCache (SHA-256 Fingerprinting)
            │
            ▼
   FrameworkDefinition ── (Decoupled Registry lookup via FrameworkRegistry)
            │
            ▼
      FrameworkGraph ── (Bounded Nodes: FRAMEWORK, ENTRYPOINT, CONFIG, MODULE)
            │
            ▼
   FrameworkPass & ArtifactStore ── (Artifacts: framework_graph, framework_registry, framework_metadata)
            │
            ▼
   FrameworkReporter ── (JSON default, Mermaid, DOT, HTML)
```

---

## Supported Framework Plugins

1. **Flask** (Python)
2. **Django** (Python)
3. **FastAPI** (Python)
4. **Express.js** (JavaScript/TypeScript)
5. **Next.js** (JavaScript/TypeScript)
6. **Laravel** (PHP)
7. **Gin** (Go)

---

## CLI Inspection Commands

```bash
# Detect frameworks in a target project
karsasec framework detect /path/to/project

# Display framework graph statistics
karsasec framework stats /path/to/project

# Export FrameworkGraph (JSON, Mermaid, DOT, HTML)
karsasec framework export /path/to/project --format json --output report.json

# Visualize FrameworkGraph topology in terminal
karsasec framework visualize /path/to/project
```
