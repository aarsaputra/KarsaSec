# Internal Contract: Medium-Level Intermediate Representation (MIR)

## Overview
`MIR` (Medium-Level Intermediate Representation) menghilangkan keanekaragaman sintaksis dan menstandardisasi seluruh operasi menjadi instruksi SSA (*Static Single Assignment*) tiga alamat (*three-address code*).

## Schema & Attributes
```json
{
  "instruction_id": "string",
  "op_code": "string (ASSIGN, CALL, RETURN, JUMP, BRANCH)",
  "operands": "List[MIROperand]",
  "result_var": "Optional[MIRVariable]",
  "scope_id": "string"
}
```

## Producer Contract
- **Producer**: `MIRBuilder`.
- **Invariants**:
  - Semua variabel hasil (`result_var`) dalam bentuk SSA harus berversi unik (`x_1`, `x_2`).
  - `op_code` harus sesuai dengan enumerasi `MIROpCode`.

## Consumer Contract
- **Consumer**: `CFGBuilder`, `DataflowEngine`.
- **Invariants**:
  - Menjamin ketersediaan informasi scope pengenal variabel.

## Failure Behaviour
- Instruksi yang tidak teridentifikasi ditransformasi menjadi `MIRNop` untuk mempertahankan kontinuitas aliran eksekusi.
