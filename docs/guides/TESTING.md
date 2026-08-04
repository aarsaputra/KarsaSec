# 🧪 KarsaSec — Testing Strategy Guide

Dokumen ini menjelaskan strategi pengujian otomatis pada repositori KarsaSec.

## Jenis Pengujian

1. **Unit Tests (`tests/unit/`):**
   Pengujian komponen individual (parser, rule matcher, di container, config loader). Berjalan cepat di lokal.

2. **Integration Tests (`tests/integration/`):**
   Pengujian CLI end-to-end dengan repositori target dummy.

3. **Golden File Tests (`tests/golden/`):**
   Pengujian output SARIF dan JSON untuk memastikan skema terstruktur tidak berubah secara tidak sengaja.

4. **Snapshot Tests (`tests/snapshot/`):**
   Pengujian tampilan Rich UI Console.

## Perintah Pengujian

```bash
# Menjalankan seluruh test suite
pytest

# Menjalankan test dengan laporan coverage
pytest --cov=karsasec --cov-report=term-missing

# Menjalankan test modul tertentu
pytest tests/test_cli.py
```
