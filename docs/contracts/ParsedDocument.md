# Internal Contract: ParsedDocument

## Overview
`ParsedDocument` mendefinisikan kontrak data hasil *parsing* berkas mentah (*source code* / *config* / *IaC*) menjadi struktur AST generik (`FileNode`).

## Schema & Attributes
```json
{
  "language": "string (e.g., Python, JavaScript, PHP, Go, Dockerfile, Kubernetes)",
  "file_path": "Path object or string",
  "root": "FileNode AST object",
  "symbol_table": "SymbolTable object",
  "diagnostics": "List[Diagnostic]",
  "parse_time_ms": "float (ms)",
  "parser_version": "string (semver)"
}
```

## Producer Contract
- **Producer**: `ParserPlugin` (`PythonParserPlugin`, `GenericParserPlugin`).
- **Invariants**:
  - `file_path` harus absolut atau teresolusi.
  - `root` tidak boleh `None` jika berkas valid dan tidak kosong.
  - `parse_time_ms` wajib bernilai non-negatif (`>= 0.0`).

## Consumer Contract
- **Consumer**: `HIRBuilder`, `PassManager`, `ScanContext`.
- **Invariants**:
  - Konsumen tidak boleh memutasi `root` AST secara *in-place*.
  - Jika `root` berstatus `None`, konsumen harus menangani sebagai berkas kosong tanpa memicu pembatalan seluruh pipeline.

## Failure Behaviour
- Jika sintaks berkas *malformed*, produsen harus mengembalikan `FileNode` parsial dengan daftar `Diagnostic` bertipe `ERROR` atau `WARNING`, bukan melemparkan unhandled exception.
