# Internal Contract: Finding

## Overview
`Finding` mendefinisikan struktur immutable akhir dari temuan kerentanan keamanan yang dihasilkan oleh KarsaSec Engine.

## Schema & Attributes
```json
{
  "finding_id": "string (UUID v4 / hash)",
  "rule_id": "string (e.g. KS-PHP-0001)",
  "rule_name": "string",
  "severity": "Severity Enum (CRITICAL, HIGH, MEDIUM, LOW, INFO)",
  "confidence": "Confidence Enum (CONFIDENT, LIKELY, POSSIBLE)",
  "file_path": "Path / string",
  "line_number": "int",
  "snippet": "string",
  "cwe": "string",
  "owasp": "string",
  "fingerprint": "string (SHA-256 deterministic hash)",
  "remediation": "string"
}
```

## Producer Contract
- **Producer**: `FindingFactory`.
- **Invariants**:
  - `finding_id` dan `fingerprint` bersifat deterministik (selalu identik untuk masukan berkas dan aturan yang sama).
  - Objek `Finding` bersifat *immutable* (Frozen Dataclass).

## Consumer Contract
- **Consumer**: `ConsoleReporter`, `JSONReporter`, `SARIFReporter`.
- **Invariants**:
  - Pelaporan tidak boleh mengubah urutan temuan tanpa aturan sorting deterministik yang jelas (diurutkan berdasarkan `file_path` -> `line_number` -> `rule_id`).
