# Internal Contract: Control Flow Graph (CFG)

## Overview
`CFG` mendokumentasikan jalur eksekusi berarah (*directed execution graph*) dari sebuah fungsi atau blok kode eksekusi.

## Schema & Attributes
```json
{
  "function_name": "string",
  "entry_node_id": "string",
  "exit_node_id": "string",
  "blocks": "Dict[str, BasicBlock]",
  "edges": "List[CFGEdge(from, to, condition_type)]"
}
```

## Producer Contract
- **Producer**: `CFGBuilder`.
- **Invariants**:
  - `entry_node_id` **tepat satu** per CFG fungsi.
  - `exit_node_id` harus ada dan terjangkau (*reachable*) dari entry.
  - Graph harus terhubung (*connected graph*), tidak boleh ada edge invalid ke simpul yang tidak terdaftar di `blocks`.

## Consumer Contract
- **Consumer**: `DataflowEngine`, `TaintAnalyzer`.
- **Invariants**:
  - Mengabaikan arah alur balik (*back-edges*) secara aman tanpa memicu *infinite loop* saat penelusuran alur.
