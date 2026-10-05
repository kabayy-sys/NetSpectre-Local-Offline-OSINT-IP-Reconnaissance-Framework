"""Laporan hasil investigasi yang diproses murni di dalam memori.

Default: semua hasil dikumpulkan ke dalam objek laporan tanpa menyentuh
disk. Opsi penyimpanan (polos atau terenkripsi) hanya terjadi bila
pengguna secara sengaja memintanya dari `main.py`.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime


class Report:
    """Kontainer hasil investigasi dengan dukungan ekspor JSON."""

    def __init__(self, target: str):
        self.target = target
        self.created_at = datetime.now().isoformat(timespec="seconds")
        self.sections: dict[str, object] = {}

    def add(self, key: str, data: object) -> None:
        """Simpang satu bagian hasil ke dalam laporan."""
        self.sections[key] = data

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "created_at": self.created_at,
            "sections": self.sections,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def save(self, path: str, password: str | None = None) -> str:
        """Simpan laporan; terenkripsi bila `password` diberikan.

        Enkripsi memakai `cryptography` (opsional). Bila belum terpasang,
        laporan jatuh ke JSON polos disertai peringatan agar prinsip
        keamanannya tetap transparan.
        """
        payload = self.to_json().encode()
        if password:
            try:
                cipher = _make_cipher(password)
            except ImportError:
                return "[ - ] 'cryptography' belum terpasang; laporan disimpan sebagai JSON polos."
            payload = cipher.encrypt(payload)
            with open(path, "wb") as fh:
                fh.write(payload)
            return f"[ + ] Laporan terenkripsi disimpan ke: {path}"

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())
        return f"[ + ] Laporan disimpan sebagai JSON ke: {path}"


def _make_cipher(password: str):
    """Kembalikan objek Fernet yang diturunkan dari kata sandi pengguna."""
    from cryptography.fernet import Fernet  # diimpor lazily agar opsional

    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
    return Fernet(key)