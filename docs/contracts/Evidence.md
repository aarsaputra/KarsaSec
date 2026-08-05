# Internal Contract: Evidence

## Overview
`Evidence` merekam bukti-bukti analisis statis (sink berbahaya, masukan pengguna, variabel terpolusi) yang mendukung pembentukan nilai *confidence*.

## Schema & Attributes
```json
{
  "rule_id": "string",
  "node_id": "string",
  "matched_symbol": "string",
  "matched_text": "string",
  "evidence_types": "List[string] (e.g. dangerous_sink, user_input)",
  "confidence_score": "float (0.0 to 1.0)"
}
```

## Producer Contract
- **Producer**: `EvidenceCollector`.
- **Invariants**:
  - `confidence_score` harus selalu berada dalam rentang `0.0 <= score <= 1.0`.

## Consumer Contract
- **Consumer**: `FindingFactory`.
- **Invariants**:
  - Memetakan `confidence_score` ke tingkatan `Confidence` Enum secara konsisten.
