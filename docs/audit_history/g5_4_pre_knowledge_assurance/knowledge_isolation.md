# Knowledge Isolation Architecture Report (INV-G5.4-02 & INV-G5.4-03)

## Conceptual & File Isolation
- **Baseline Engine**: Frozen in `karsasec/analysis/`, `karsasec/data/`, `karsasec/rules/`.
- **Knowledge Expansion**: Isolated in `benchmarks/k1/` and future `karsasec/rules/patterns/k1/`.

---

## Classification Engine (`classify_change`)
- `KNOWLEDGE_ONLY`: Only expansion pack files modified.
- `ENGINE_CHANGE_REQUIRED`: Core detector engine modified (forces new certification cycle).
- `BENCHMARK_MUTATION`: Historical benchmark files modified (FORBIDDEN).
- `EVALUATOR_MUTATION`: Evaluator logic modified (FORBIDDEN).
