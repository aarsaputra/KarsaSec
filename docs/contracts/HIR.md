# Internal Contract: High-Level Intermediate Representation (HIR)

## Overview
`HIR` (High-Level Intermediate Representation) mempertahankan sintaksis spesifik bahasa namun menyederhanakan variasi AST menjadi simpul semantik universal.

## Schema & Attributes
```json
{
  "hir_id": "string (unique node identifier)",
  "node_type": "string (e.g. HIRExpression, HIRFunctionDecl, HIRAssign)",
  "language": "string",
  "source_span": "Position(start, end)",
  "children": "List[HIRNode]",
  "attributes": "Dict[str, Any]"
}
```

## Producer Contract
- **Producer**: `HIRBuilder`.
- **Invariants**:
  - Setiap simpul HIR harus memiliki `hir_id` unik dalam berkas.
  - `source_span` tidak boleh `None` dan harus merujuk pada rentang baris/kolom valid pada berkas sumber.
  - Tidak boleh ada simpul yatim (*orphan node*) yang tidak terhubung dari akar `HIRFile`.

## Consumer Contract
- **Consumer**: `MIRBuilder`, `SymbolResolver`.
- **Invariants**:
  - Konsumen dapat memperbanyak (*clone*) HIR namun tidak boleh memutasi `hir_id` asli.

## Failure Behaviour
- Kegagalan konversi AST ke HIR pada simpul tertentu harus membungkus simpul dalam `HIRUnknownNode` tanpa menghentikan pemrosesan simpul saudara (*sibling nodes*).
