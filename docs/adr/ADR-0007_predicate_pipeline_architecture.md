# ADR-0007: Modular Predicate Pipeline Architecture for AST Matcher

## Status
Accepted

## Context
In Sprint 3B-2, KarsaSec requires a high-performance, deterministic AST rule matching engine. Early designs proposed a monolithic `PredicateEngine` class that performed all node, language, symbol, and regex checks in a single file. As the engine scales to support Control Flow Graph (CFG), Data Flow Graph (DFG), and Type Resolution in Sprint 4+, a monolithic predicate class would turn into an unmaintainable God Object.

## Decision
We decouple predicate evaluation into modular, single-responsibility predicate plugins located under `karsasec.rules.matcher.predicates`:
- `NodeTypePredicate`: Evaluates language and AST node type scope with instant short-circuiting.
- `SymbolPredicate`: Evaluates symbol triggers against node identifiers and `SymbolTable` entries.
- `RegexPredicate`: Evaluates pre-compiled `re.Pattern` regex expressions against node text.
- `LiteralPredicate`: Evaluates string literal triggers.
- `PredicatePipeline`: Orchestrates execution in a strict short-circuiting order: `Language/NodeType -> Symbol -> Regex -> Literal`.

Rule compilation (`RuleCompiler`) converts raw `Rule` definitions into `CompiledRule` objects, pre-compiling all regular expressions ahead of time to eliminate runtime regex compilation overhead.

## Consequences
- **Positive**: Sprint 4 can add complex graph predicates (e.g., `TaintFlowPredicate`, `CFGPathPredicate`) without modifying `ASTMatcher` or breaking existing AST predicates.
- **Positive**: Short-circuiting order guarantees that expensive operations (like regex evaluation) are never invoked if language or node type mismatch occurs.
- **Negative**: Slightly higher file count, offset by much higher code clarity and testability.
