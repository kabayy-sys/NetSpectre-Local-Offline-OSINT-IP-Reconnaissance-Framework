"""Pembuat password rahasia untuk lab latihan; hanya hash yang disimpan.

Umumnya de menyimpan kata asli ke disk sehingga pembuat lab (yaitu kamu)
pun tidak mengetahui kata sandinya — penyelesaian hanya dapat diperoleh
melalui latihan enumerasi menggunakan wordlist.
"""

from __future__ import annotations

import argparse
import hashlib
import random
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent
HASH_FILE = BASE_DIR / "password.hash"
PASSWORD_LIST = BASE_DIR / "passwords.txt"


def load_candidates() -> list[str]:
    """Baca daftar kata calon password dari file."""
    words = [
        word.strip()
        for word in PASSWORD_LIST.read_text(encoding="utf-8").splitlines()
        if word.strip()
    ]
    if not words:
        print(f"[-] '{PASSWORD_LIST.name}' kosong atau tidak ditemukan.")
        sys.exit(1)
    return words


def hash_password(password: str) -> str:
    """Kembalikan SHA-256 hex dari sebuah kata sandi."""
    return hashlib.sha256(password.encode()).hexdigest()


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        description="Buat password rahasia latihan (hanya hash yang disimpan)."
    )
    parser.add_argument(
        "--password", default=None,
        help="Set kata sandi tertentu (opsional; default dipilih acak dari wordlist).",
    )
    parser.add_argument(
        "--with-number", action="store_true",
        help="Tambahkan angka 2 digit acak di belakang kata (mis. 'shadow74').",
    )
    parser.add_argument(
        "--show", action="store_true",
        help="Tampilkan kata sandi asli (misalnya saat perlu reset).",
    )
    args = parser.parse_args(argv)

    if args.password:
        chosen = args.password
    else:
        base = random.choice(load_candidates())
        chosen = base + (str(random.randint(10, 99)) if args.with_number else "")

    HASH_FILE.write_text(hash_password(chosen), encoding="utf-8")
    print(f"[ + ] Password rahasia dibuat, hash disimpan ke '{HASH_FILE.name}'.")
    if args.show:
        print(f"[ i ] Kata sandi asli (untuk reset): {chosen}")
    else:
        print("[ i ] Kata sandi asli TIDAK ditampilkan.")
        print("      Latih menemukannya dengan: ")
        print("      python main.py -t http://127.0.0.1:PORT --brute-http "
              "--users login_lab/users.txt --passwords login_lab/passwords.txt --confirm-lab")
    print(f"[ i ] Hash SHA-256: {hash_password(chosen)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())