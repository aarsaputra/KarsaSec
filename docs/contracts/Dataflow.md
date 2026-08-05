# Internal Contract: Dataflow & Taint Analysis

## Overview
`Dataflow` mendokumentasikan pelacakan alur data terkontaminasi (*tainted flow*) dari *Source* menuju *Sink*.

## Schema & Attributes
```json
{
  "source": "TaintSource(var_name, location)",
  "sink": "TaintSink(function_name, location)",
  "path": "List[TaintStep(node_id, var_name, span)]",
  "is_sanitized": "boolean"
}
```

## Producer Contract
- **Producer**: `DataflowEngine`.
- **Invariants**:
  - `source` dan `sink` wajib ada dan valid.
  - Alur `path` terhubung secara linier dan berurutan dari source hingga sink.
  - Variabel terisolasi (*orphan variable*) tidak dimasukkan ke dalam rantai `path`.

## Consumer Contract
- **Consumer**: `EvidenceCollector`, `RuleMatcher`.
- **Invariants**:
  - Mengonversi alur taint menjadi bukti deterministik untuk penghitungan skor *confidence*.
