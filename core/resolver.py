"""Penerjemah antara domain dan alamat IP menggunakan socket bawaan Python.

Modul ini hanya memakai pustaka standar sehingga aman berjalan secara
lokal tanpa kebutuhan koneksi ke API pihak ketiga.
"""

from __future__ import annotations

import ipaddress
import socket


def is_valid_ip(value: str) -> bool:
    """Kembalikan True jika string adalah alamat IP (IPv4/IPv6) yang valid."""
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def resolve_target(target: str) -> dict:
    """Terjemahkan input pengguna menjadi pasangan hostname dan IP.

    - Jika input berupa IP, cari hostname (reverse DNS) miliknya.
    - Jika input berupa domain, cari alamat IP miliknya.

    Kembalikan dict ``status=success`` beserta "target" dan "ip",
    atau dict ``status=error`` berisi pesan kesalahan yang mudah dibaca.
    """
    target = target.strip()
    if not target:
        return {"status": "error", "message": "Target tidak boleh kosong."}

    try:
        if is_valid_ip(target):
            ip = target
            hostname = socket.gethostbyaddr(target)[0]
        else:
            hostname = target
            ip = socket.gethostbyname(target)
        return {"status": "success", "target": hostname, "ip": ip}
    except socket.gaierror:
        return {
            "status": "error",
            "message": f"Target '{target}' tidak dapat diselesaikan (host tidak ditemukan).",
        }
    except socket.herror:
        return {
            "status": "error",
            "message": f"Tidak ada catatan hostname untuk alamat IP '{target}'.",
        }
    except OSError as exc:
        return {"status": "error", "message": f"Terjadi kesalahan jaringan: {exc}."}