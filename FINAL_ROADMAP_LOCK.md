# FINAL_ROADMAP_LOCK.md — KarsaSec

Status: **GOVERNING DOCUMENT** — mengikat untuk seluruh AI agent, kontributor, dan reviewer yang bekerja pada KarsaSec E17–E21.

---

## 1. Status Sprint & Validation Phase

| Phase / Sprint | Nama                                | Status                          |
|----------------|--------------------------------------|----------------------------------|
| E9             | CPG / Query                          | FROZEN                          |
| E10            | Semantic Facts                       | FROZEN                          |
| E11            | Semantic Flow / Correlation          | FROZEN                          |
| E12            | Security Rule Engine / Findings      | FROZEN                          |
| E13            | Finding Correlation / Evidence       | FROZEN                          |
| E14            | Priority / Remediation / Regression  | FROZEN                          |
| E15            | Security Decision Gate               | FROZEN                          |
| E16            | Release Admission / Enforcement      | FROZEN                          |
| **V0**         | **Foundation Real-World Validation** | **PASSED**                      |
| E17            | Security Control Plane               | **PASSED**                      |
| E18            | Continuous Security Verification     | **PASSED**                      |
| E19            | Threat Intelligence & Risk Context   | **PASSED**                      |
| E20            | Autonomous Security Operations       | **PASSED**                      |
| E21            | Independent Security Readiness Review| **INTERNAL READINESS CERTIFIED**|

**V0 + E17–E21 adalah roadmap akhir yang dikunci.** Tidak ada penambahan sprint (E22+) sebagai default; lihat §4 untuk prosedur pengecualian.

---

## 2. Prinsip Freeze

Begitu satu sprint/fase disertifikasi:

- Kode sprint tersebut **tidak boleh diubah** oleh sprint-sprint berikutnya (no upstream mutation).
- Sprint di atasnya hanya boleh **membaca (read-only)** output/kontrak sprint yang sudah frozen, tidak mendesain ulang.
- Perubahan apa pun terhadap sprint yang sudah frozen wajib melalui **prosedur unfreeze** (§4), bukan workaround diam-diam di layer atas.

---

## 3. Exit Criteria E21 (Wajib Sebelum Dinyatakan "Selesai")

E21 tidak boleh dinyatakan lulus hanya karena test suite internal hijau. Kriteria keluar berikut wajib dipenuhi:

### 3.1 Verifikasi Teknis
- Unit tests ≥ 300, invariant kumulatif ≥ 200, adversarial cases kumulatif ≥ 200, metamorphic tests ≥ 100 — **dengan catatan**: setiap angka ini harus disertai peta risk-coverage (lihat §3.4), bukan sekadar dipenuhi sebagai kuota.
- Determinism check lolos di ≥3 `PYTHONHASHSEED` berbeda.
- Ruff, static security scan, dependency audit, freeze audit: PASS.

### 3.2 Review Independen (di luar AI agent penulis kode/spec)
- Minimal satu manusia yang **bukan** penulis spec/kode sprint terkait wajib melakukan review manual terhadap:
  - E17 (Control Plane) — potensi bypass enforcement.
  - E19 (Threat Model) — asumsi bobot risk-scoring dan batas determinism vs data time-varying.
  - E20 (Autonomous Ops) — capability model dan action authorization.
- Sertifikasi E21 **tidak sah** tanpa sign-off review ini. AI agent tidak dapat mensertifikasi pekerjaannya sendiri sebagai final.

### 3.3 Shadow-Mode Observation untuk E20 (Wajib)
- E20 tidak boleh dianggap "certified for production autonomous action" tanpa minimal **4–8 minggu masa shadow-mode**: sistem mengusulkan action (`ActionProposal`) tetapi eksekusi tetap memerlukan approval manusia.
- Selama shadow-mode, catat: rasio false-positive proposal, rasio action yang di-reject reviewer, insiden near-miss.
- Baru setelah metrik shadow-mode memenuhi ambang yang disepakati, capability eksekusi otomatis diaktifkan bertahap.

### 3.4 Risk-Coverage Mapping
- Setiap failure mode kritis yang terdaftar di ERD/invariant masing-masing sprint (E17–E20) wajib punya minimal satu adversarial test yang secara eksplisit ditandai mengcover failure mode tersebut.
- Dokumen mapping ini (`docs/RISK_COVERAGE_MATRIX.md`) adalah syarat E21, terpisah dari angka test count.

### 3.5 Circuit Breaker & Blast Radius (E20)
- E20 wajib punya batas operasional eksplisit sebelum sertifikasi:
  - `max_auto_block_per_window`
  - `max_actions`, `action_budget`, `time_budget`, `retry_budget`
- Tanpa nilai konkret untuk parameter ini, E20 tidak lolos exit criteria.

### 3.6 Labeling
- Output akhir E21 disebut **"Internal Readiness Review"**, bukan "Enterprise Security Certification", kecuali benar-benar ada audit pihak ketiga independen (mis. SOC2, pentest eksternal) yang mendukung klaim tersebut.

---

## 4. Prosedur Unfreeze (Pengecualian terhadap §2)

Unfreeze terhadap sprint yang sudah frozen (E9–E20) hanya boleh terjadi jika:

1. Ditemukan **flaw fundamental** pada sprint frozen tersebut selama V0 validation atau pengerjaan sprint di atasnya.
2. Diajukan sebagai **proposal unfreeze tertulis** yang menjelaskan: flaw yang ditemukan, dampak terhadap sprint-sprint di atasnya, dan scope perubahan minimal yang diperlukan.
3. Disetujui oleh reviewer manusia yang sama seperti §3.2 (bukan AI agent).
4. Setelah unfreeze dan perbaikan, sprint tersebut **wajib disertifikasi ulang** sepenuhnya.

---

## 5. Global Security Contract (Rujukan)

- **Rule 01**: No Upstream Mutation (E9–E16 frozen)
- **Rule 02**: UNKNOWN Always Fail Closed
- **Rule 03**: Missing Evidence $\rightarrow$ UNKNOWN (bukan LOW RISK)
- **Rule 04**: Invalid Data (NaN/Inf/negative/dst) $\rightarrow$ INVALID/UNKNOWN
- **Rule 05**: Determinism (berlaku untuk struktur/logika, bukan data time-varying)
- **Rule 06**: No Security Downgrade tanpa fresh valid evaluation
- **Rule 07**: Semua transisi security-critical wajib diaudit
