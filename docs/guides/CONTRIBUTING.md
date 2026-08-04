# 🤝 Contributing to KarsaSec

Terima kasih atas minat Anda untuk berkontribusi pada KarsaSec! Dokumen ini memberikan panduan singkat mengenai kontribusi open-source.

## Kode Etik
Kami berkomitmen untuk menjaga lingkungan kontribusi yang ramah, inklusif, dan bebas dari pelecehan.

## Alur Kontribusi (Pull Request)

1. **Fork Repositori** dan buat branch fitur baru dari `main`:
   ```bash
   git checkout -b feature/nama-fitur-anda
   ```

2. **Tulis Kode & Test Unit:**
   Setiap penambahan fitur atau perbaikan bug wajib menyertakan unit test terkait di folder `tests/`.

3. **Jalankan Verifikasi Lokal:**
   ```bash
   ruff check .
   mypy karsasec
   pytest
   ```

4. **Kirimkan Pull Request (PR):**
   Sertakan deskripsi jelas mengenai perubahan yang dibuat dan kaitkan dengan Issue ID jika ada.
