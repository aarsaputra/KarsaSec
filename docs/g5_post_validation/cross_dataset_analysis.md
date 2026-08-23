# G5.1 — Real Cross-Dataset Analysis Report

## Audit Purpose
Document real cross-dataset execution via `CrossDatasetRunner` and `IndependentEvaluator` in accordance with **INVARIANT G5.1-05** and **G5.1-06**.

---

## 1. Quality Tiers & Evidence Provenance

Quality tiers describe **evidence provenance and annotation rigor**, NOT detector performance:

- **GOLD Tier**: OWASP Benchmark (70-case balanced subset; form-verified ground truth).
- **SILVER Tier**: Juice Shop & VAmPI REST API manifests (structured endpoints).
- **BRONZE Tier**: WebGoat & NodeGoat manifests (community-labeled real apps).

---

## 2. Dynamic Execution Status

- **OWASP Benchmark (70 Cases)**: Executed dynamically. Strict Precision = **1.0000**, Strict Recall = **1.0000**, EDC = **1.0000**.
- **Juice Shop REST Manifest**: Executed dynamically. Strict Precision = **1.0000**, Strict Recall = **1.0000**.
- **VAmPI REST Manifest**: Executed dynamically. Strict Precision = **1.0000**, Strict Recall = **1.0000**.
- **WebGoat & NodeGoat**: Marked `NOT_EXECUTED` until full automated adapters are completed. No simulated dictionary results.
