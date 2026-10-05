"""Fingerprinting layanan dengan membaca banner pada port yang terbuka.

Banner sering mengandung nama dan versi perangkat lunak, sehingga berguna
untuk memahami layanan yang berjalan pada sebuah mesin lab.
"""

from __future__ import annotations

import socket

DEFAULT_TIMEOUT = 3.0
_MAX_BANNER_LENGTH = 500


def _probe_data(host: str, port: int) -> bytes:
    """Susun data awal yang mendorong layanan untuk mengirim banner."""
    if port in (80, 8080):
        return f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
    if port in (25, 587):
        return b"EHLO example.com\r\n"
    return b"\r\n"


def grab_banner(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Baca banner satu layanan pada port tertentu dalam batas waktu."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            probe = _probe_data(host, port)
            if probe:
                sock.sendall(probe)
            data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass  # waktu habis dianggap selesai membaca banner
        banner = data.decode("utf-8", errors="replace").strip()
        return banner[:_MAX_BANNER_LENGTH] if banner else "(tidak ada banner)"
    except OSError:
        return "(gagal membaca banner)"


def grab_banners(
    host: str,
    ports: list[int],
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[int, str]:
    """Grab banner untuk sejumlah port dan kembalikan sebagai dict port -> banner."""
    return {port: grab_banner(host, port, timeout) for port in ports}