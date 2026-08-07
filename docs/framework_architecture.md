# Framework Semantic Layer Architecture

## 1. Overview & Pipeline

KarsaSec Framework Semantic Layer abstracts web frameworks into unified, framework-agnostic semantic models.

```
Source Code / AST / CPG
         │
         ▼
Framework Detector & Manifest Loader
         │
         ▼
Semantic Extractors (collect -> validate -> emit)
         │
         ▼
Intermediate Semantic Representation (ISR Schema v1.0)
         │
         ▼
Framework Graph Builder (Immutable Graph Construction)
         │
         ▼
Framework Semantic Graph (Deterministic Node/Edge Model)
```

## 2. Core Principles
- **Framework Independence**: Security rules target unified abstractions like `Framework.Route.Unprotected` rather than framework-specific AST nodes.
- **Deterministic Canonicalization**: Deterministic SHA-256 node IDs ensure 100% reproducible analysis.
- **Graph Immutability**: Semantic graphs are frozen post-construction to guarantee query safety.
