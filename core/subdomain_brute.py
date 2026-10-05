"""Enumerasi subdomain dengan wordlist lokal menggunakan brute-force paralel.

Pencarian dilakukan dengan menyelesaikan ``word.subdomain`` lewat DNS
menggunakan ``socket`` secara multi-threading agar jauh lebih cepat
dari cara berurutan.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

DEFAULT_WORDLIST = [
    "www",
    "mail",
    "ftp",
    "webmail",
    "ns1",
    "ns2",
    "api",
    "app",
    "blog",
    "dev",
    "test",
    "stage",
    "admin",
    "portal",
    "vpn",
    "remote",
    "support",
    "siakad",
    "elearning",
    "pmb",
    "student",
    "staff",
    "library",
    "jurnal",
    "payment",
    "cdn",
    "cloud",
    "docs",
    "forum",
    "shop",
    "store",
]


def resolve_subdomain(subdomain: str) -> dict | None:
    """Coba selesaikan satu subdomain; None bila tidak terdaftar di DNS."""
    try:
        ip = socket.gethostbyname(subdomain)
    except (socket.gaierror, OSError):
        return None
    return {"subdomain": subdomain, "ip": ip}


def bruteforce_subdomains(
    domain: str,
    wordlist: list[str] | None = None,
    threads: int = 20,
    on_found: Callable[[dict], None] | None = None,
) -> list[dict]:
    """Scan subdomain dari wordlist secara paralel dan kembalikan yang ditemukan.

    ``on_found`` bersifat opsional; jika diberikan, akan dipanggil dengan
    dict ``{"subdomain": ..., "ip": ...}`` setiap kali subdomain aktif
    ditemukan (tanpa mengganggu pengambilan hasil akhir).
    """
    domain = domain.strip().lower()
    if not domain:
        raise ValueError("Domain tidak boleh kosong.")

    words = wordlist or DEFAULT_WORDLIST
    if not words:
        return []

    targets = [f"{word}.{domain}" for word in words]
    found: list[dict] = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolve_subdomain, sub): sub for sub in targets}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception:
                continue
            if result:
                found.append(result)
                if on_found:
                    on_found(result)

    return _deduplicate(found)


def _deduplicate(items: list[dict]) -> list[dict]:
    """Hapus duplikat subdomain dan urutkan menurut abjad."""
    seen: set[str] = set()
    unique: list[dict] = []
    for item in items:
        key = item["subdomain"]
        if key not in seen:
            seen.add(key)
            unique.append(item)
    unique.sort(key=lambda item: item["subdomain"])
    return unique