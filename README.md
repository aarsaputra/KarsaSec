# 🛡️ KarsaSec

> **Autonomous Application Security Operating System (SecOS)**

KarsaSec adalah platform keamanan aplikasi modern yang menggabungkan analisis deterministik berbasis AST (Abstract Syntax Tree), rule matching OWASP/CWE, Code Property Graph (CPG) berbasis SQLite lokal, dan penalaran agen AI terstruktur untuk mendampingi pengembang di sepanjang alur kerja SSDLC.

---

## ⚡ Quick Start

```bash
# Instalasi KarsaSec
pip install karsasec

# Pemindaian repositori proyek
karsasec scan .

# Audit keamanan mendalam
karsasec review .

# Diagnostik konfigurasi & lingkungan
karsasec doctor
```

---

## 📚 Dokumentasi

Dokumentasi proyek KarsaSec terstruktur secara modular di folder `docs/`:

- **[Implementation Roadmap](docs/IMPLEMENTATION_ROADMAP.md)** — Peta jalan eksekusi Sprint 0 s/d Sprint 9
- **[Project Blueprint](docs/blueprint/PROJECT_BLUEPRINT.md)** — Visi arsitektur SecOS & paradigma platform
- **[Agent Specifications](docs/architecture/AGENT_SPECIFICATIONS.md)** — Spesifikasi sistem agen & topologi DAG
- **[Research Foundation](docs/research/RESEARCH_FOUNDATION.md)** — Fondasi akademis & riset arsitektur
- **[Development Guide](docs/guides/DEVELOPMENT.md)** — Panduan setup lingkungan pengembang
- **[Contributing Guide](docs/guides/CONTRIBUTING.md)** — Panduan alur kontribusi open-source
- **[Testing Strategy](docs/guides/TESTING.md)** — Strategi pengujian & skema test suite

---

## 🛡️ Lisensi

Diterbitkan di bawah lisensi [Apache 2.0](LICENSE).
