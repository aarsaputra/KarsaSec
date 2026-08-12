# 02 — sast-skills Architecture Analysis

**Repository**: `utkusen/sast-skills`  
**Studied Commit**: `db52227eab1043bf122cbff7206fac6708b4d6c9`  
**Primary Language**: Markdown / Prompt Engineering / Agent Workflows  
**License**: MIT  

---

## 1. System Architecture & Component Inventory

`sast-skills` is an agentic security assessment skill framework designed for Claude/AI Agent environments. It defines structured workflows, prompt constraints, and subagent orchestration for performing static analysis and threat modeling across codebases.

```text
Codebase Directory
        │
        ▼
Step 1: Codebase Analysis & Threat Modeling (`sast-analysis`)
        │ (Generates `sast/architecture.md`)
        ▼
Step 2: Parallel Vulnerability Detection Subagents
   ├──► `sast-sqli`           ──► `sast/sqli-results.md`
   ├──► `sast-xss`            ──► `sast/xss-results.md`
   ├──► `sast-rce`            ──► `sast/rce-results.md`
   ├──► `sast-pathtraversal`  ──► `sast/pathtraversal-results.md`
   ├──► `sast-fileupload`     ──► `sast/fileupload-results.md`
   └──► ... (13 category agents)
        │
        ▼
Step 3: Consolidated Report Generation (`sast-report`)
        │
        ▼
Final Executive Audit Report (`sast/final-report.md`)
```

### Key Skill Workflows (`sast-files/.agents/skills/`)
- `sast-analysis`: Performs initial codebase architecture discovery, framework identification, entry point mapping, and data flow modeling.
- Category Skills (`sast-sqli`, `sast-xss`, `sast-rce`, `sast-pathtraversal`, etc.): Specialized prompts providing domain-specific threat checklists, sink patterns, and verification instructions to guide subagent code inspection.
- `sast-report`: Aggregates findings from individual Markdown reports, eliminates duplicates, ranks severity based on impact/exploitability, and formats the output.

---

## 2. AI Authority vs. Deterministic Detection Boundaries

### Where AI is Used
- **Threat Modeling & Architectural Discovery**: Identifying application entry points, authentication mechanisms, and dynamic router patterns that standard static rules may miss.
- **Contextual Verification**: Reading source code around detected sinks to assess whether custom sanitizers or authorization checks render a flow non-exploitable.
- **Explanations & Remediation**: Generating human-readable vulnerability writeups, proof-of-concept scenarios, and code patches.

### Where AI Fails / Non-Determinism Risks
- **Hallucinations & Non-Reproducibility**: Without a formal AST graph or dataflow solver, LLM-based detection produces variable results across runs on identical code.
- **Dataflow Blindness**: AI agents struggle to accurately trace complex multi-hop taint propagations across large codebases or interprocedural call trees without formal IR graphs.
- **Lack of Hard Invariants**: AI cannot guarantee 100% recall or 0% false negative rates because it evaluates code heuristically rather than deterministically.

---

## 3. Architectural Lessons for KarsaSec

### Patterns KarsaSec SHOULD Consider
- **Layered Vulnerability Taxonomy**: Categorizing analysis into clear vulnerability classes (SQLi, XSS, RCE, Path Traversal) with dedicated semantic rules and sink contexts.
- **Architectural Recon Context**: Understanding global application structure (framework entry points, global middleware, router maps) before evaluating sink expressions.

### Patterns KarsaSec SHOULD NOT Copy
- **Delegating Vulnerability Discovery to Unconstrained LLM Prompts**: Replacing deterministic SAST parsing/dataflow with LLM prompt execution violates KarsaSec's core invariant (**Deterministic security detection MUST remain authoritative**).
- **Unstructured Markdown Evidence**: Storing findings as unstructured text files rather than strongly typed `CandidateFinding` / `DataFlowEvidence` schema models prevents programmatic qualification and automated regression verification.
