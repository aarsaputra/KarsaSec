# Changelog

## Unreleased

- Add Rust and Java support for language detection and parser registration.
- Extend target detector to recognize `.rs` and `.java` source files.
- Add generic parser fallback support for Rust and Java if Tree-sitter grammars are unavailable.
- Expand CLI scan file extension support to include Rust and Java.
- Add unit tests for Rust/Java parser support and target detection.
- Add Rust and Java SSRF rule definitions and security corpus suites.
- Add hybrid RAG-enabled scan support with external corpus path injection via `--rag-corpus`.
- Add RAG context propagation into AST visitor evaluation and predicate pipeline.
- Add localized OWASP corpus scan validation for `pos_kasir/backend` with zero RAG-enabled findings after tuning.
