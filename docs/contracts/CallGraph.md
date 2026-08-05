# Internal Contract: Call Graph

## Overview
`CallGraph` memetakan relasi pemanggilan antar fungsi (*caller -> callee*) secara lintas modul dan berkas.

## Schema & Attributes
```json
{
  "nodes": "Dict[str, CallNode(function_name, file_path)]",
  "edges": "List[CallEdge(caller_id, callee_id, call_site_span)]"
}
```

## Producer Contract
- **Producer**: `CallGraphBuilder`.
- **Invariants**:
  - `caller_id` dan `callee_id` harus terdaftar dalam `nodes`.
  - Tidak boleh ada *duplicate edge* identik untuk *call site* yang sama.
  - Rekursi dipetakan sebagai *self-edge* teridentifikasi.

## Consumer Contract
- **Consumer**: `InterproceduralDataflowEngine`, `ImpactAnalyzer`.
- **Invariants**:
  - Penanganan simbol tak dikenal (*unknown symbol*) dilakukan dengan penandaan simpul eksternal/unresolved tanpa menghentikan traversal.
