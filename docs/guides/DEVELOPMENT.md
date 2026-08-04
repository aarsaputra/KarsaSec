# 💻 KarsaSec — Development Guide

Panduan setup lingkungan pengembangan lokal untuk kontributor KarsaSec.

## Prasyarat Lingkungan
- **Python:** 3.11 atau lebih baru
- **Package Manager:** `pip` atau `uv` / `poetry`
- **Git:** 2.30+

## Quick Start Development

1. **Clone Repositori:**
   ```bash
   git clone https://github.com/karsasec/karsasec.git
   cd karsasec
   ```

2. **Buat & Aktifkan Virtual Environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install KarsaSec dalam Mode Editable (dengan dev dependencies):**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Verifikasi Instalasi CLI:**
   ```bash
   karsasec --help
   karsasec doctor
   ```

## Workflow Code Quality

Sebelum melakukan commit, pastikan kode lulus pemeriksaan berikut:

```bash
# Format & Linting dengan Ruff
ruff check .
ruff format .

# Type Checking dengan Mypy
mypy karsasec

# Menjalankan Test Suite
pytest
```
