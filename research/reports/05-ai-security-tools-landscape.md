# 05 — AI-Assisted Security Tools Landscape Analysis

**Repository**: `scadastrangelove/awesome-ai-security-tools`  
**Studied Commit**: `6a83a27c43895a333c909d2d5d4312b15502d661`  
**Primary Function**: Curated taxonomy of AI/LLM-powered security tools, SAST assistants, vulnerability auto-fixers, and security agent frameworks.

---

## 1. AI Security Ecosystem Taxonomy

Analysis of modern AI security tooling reveals four operational tiers based on where AI is integrated in the vulnerability lifecycle:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      AI Security Tool Taxonomy                         │
├─────────────────┬───────────────────────┬──────────────────────────────┤
│ Tier            │ Examples              │ Primary Function             │
├─────────────────┼───────────────────────┼──────────────────────────────┤
│ 1. AI Triage &  │ DeepCode AI,          │ Filters FP alerts produced   │
│    Qualification│ Snyk Code             │ by SAST tools using LLM.     │
├─────────────────┼───────────────────────┼──────────────────────────────┤
│ 2. Automated    │ Pixeebot, Copilot     │ Generates PR code patches    │
│    Remediation  │ Security Autofix      │ for confirmed vulnerabilities│
├─────────────────┼───────────────────────┼──────────────────────────────┤
│ 3. Autonomous   │ sast-skills,          │ Agentic prompt loops executing│
│    Pentesting   │ Agentic SAST          │ security checks on repos.    │
├─────────────────┼───────────────────────┼──────────────────────────────┤
│ 4. Deterministic│ KarsaSec              │ Deterministic AST/DFG engine │
│    Engine + AI  │ Architecture          │ acts as authoritative truth; │
│    Explanations │                       │ AI assists in explanations.  │
└─────────────────┴───────────────────────┴──────────────────────────────┘
```

---

## 2. Deterministic vs. Probabilistic Security Boundaries

A critical finding from studying AI security implementations is the conflict between **probabilistic LLM generation** and **deterministic security requirements**:

| Operational Requirement | Deterministic SAST Engine (KarsaSec) | Probabilistic AI Model (LLM Agent) |
| :--- | :--- | :--- |
| **Reproducibility** | 100% (Identical code produces identical output). | Non-deterministic (Varies by seed/temperature). |
| **Recall Guarantee** | High (Proven AST pattern matching & DFG edges). | Variable (May hallucinate or overlook lines). |
| **Auditability & Provenance**| Exact AST nodes, line numbers, DFG hops. | Black-box prompt token generation. |
| **Speed / Cost** | Sub-second local execution (Zero API costs). | Multi-second network calls (High API cost). |

---

## 3. Strict AI Authority Boundaries for KarsaSec

To preserve KarsaSec's core invariants, the architectural authority boundaries MUST be enforced as follows:

```text
   ┌─────────────────────────────────────────────────────────────────┐
   │                  AUTHORITATIVE CORE (Deterministic)             │
   │                                                                 │
   │  Parsing ──► AST ──► Universal IR ──► DFG ──► Qualification      │
   │                                                    │            │
   └────────────────────────────────────────────────────┼────────────┘
                                                        │ Confirmed Findings & Evidence
                                                        ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │                  AUXILIARY LAYER (AI / LLM)                     │
   │                                                                 │
   │  - Explanation Generation & Vulnerability Context Summaries     │
   │  - Suggested Patch / Remediation Generation                     │
   │  - Natural Language Rule Synthesis                              │
   └─────────────────────────────────────────────────────────────────┘
```

### Invariants:
1. **AI MUST NOT determine candidate inclusion or rejection**: Detection and qualification decisions MUST remain 100% deterministic and explainable.
2. **AI MUST NOT override AST/DFG evidence**: If the deterministic graph proves taint reaches an unguarded sink, an AI prompt MUST NOT suppress the finding.
3. **AI output is metadata, not primary evidence**: AI summaries may accompany a finding as auxiliary context, but the primary evidence must consist of concrete `ASTNode` and `DataFlowEvidence` structures.
