"""Pemindai port TCP (connect scan) untuk target yang sah (lab).

Membuka koneksi ke tiap port secara paralel untuk menentukan port mana
yang terbuka pada mesin target. Hanya boleh dijalankan pada target yang
memang berada di lingkungan lab / telah diizinkan.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_TIMEOUT = 1.0


def expand_ports(ports_spec: str) -> list[int]:
    """Ubah spec seperti '22,80,443,1000-2000' menjadi daftar port unik."""
    ports: list[int] = []
    seen: set[int] = set()
    for part in ports_spec.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            start_raw, end_raw = part.split("-", 1)
            start, end = int(start_raw), int(end_raw)
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"Rentang port tidak valid: {part}")
            values = range(start, end + 1)
        else:
            value = int(part)
            if not 1 <= value <= 65535:
                raise ValueError(f"Port tidak valid: {part}")
            values = [value]

        for port in values:
            if port not in seen:
                seen.add(port)
                ports.append(port)
    return ports


def probe_port(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Kembalikan True bila koneksi TCP ke port tersebut berhasil dibuka."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_ports(
    host: str,
    ports: list[int],
    threads: int = 100,
    timeout: float = DEFAULT_TIMEOUT,
) -> list[int]:
    """Pindai daftar port secara paralel dan kembalikan yang terbuka."""
    open_ports: list[int] = []
    if not ports:
        return open_ports

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(probe_port, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                is_open = future.result()
            except Exception:
                continue
            if is_open:
                open_ports.append(port)

    open_ports.sort()
    return open_ports