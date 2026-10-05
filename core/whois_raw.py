"""Query data WHOIS langsung melalui TCP port 43 tanpa API pihak ketiga.

Modul ini membuka koneksi socket manual ke server registri (IANA, ARIN,
RIPE, dst.) sehingga tidak bergantung pada pustaka atau layanan berbayar.
"""

from __future__ import annotations

import socket

DEFAULT_SERVER = "whois.iana.org"
DEFAULT_PORT = 43
TIMEOUT = 8

# Kata kunci untuk menyaring baris penting dari output WHOIS.
_SUMMARY_KEYWORDS = (
    "inetnum",
    "netname",
    "org-name",
    "country",
    "netrange",
    "nserver",
    "registrar",
    "created",
    "updated",
)


def extract_summary(raw_text: str) -> str:
    """Saring bagian terpenting dari output WHOIS agar ringkas.

    Jika tidak ada baris yang cocok, keseluruhan teks dikembalikan agar
    tidak ada informasi berharga yang hilang.
    """
    lines = []
    for line in raw_text.splitlines():
        clean = line.lower().lstrip()
        if any(clean.startswith(keyword) for keyword in _SUMMARY_KEYWORDS):
            lines.append(line.strip())
    return "\n".join(lines) if lines else raw_text.strip()


def query_whois(
    ip_address: str,
    server: str = DEFAULT_SERVER,
    timeout: int = TIMEOUT,
) -> str:
    """Kirim query WHOIS ke server registri dan kembalikan hasil mentah.

    Seluruh koneksi ditutup otomatis lewat context manager ``with``.
    Setiap kegagalan dikembalikan sebagai pesan teks yang jelas, bukan
    exception yang menghentikan program utama.
    """
    try:
        with socket.create_connection((server, DEFAULT_PORT), timeout=timeout) as sock:
            sock.sendall(f"{ip_address}\r\n".encode("utf-8"))
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response.decode("utf-8", errors="ignore")
    except socket.timeout:
        return f"[-] Timeout saat menghubungi {server}:{DEFAULT_PORT}."
    except socket.gaierror:
        return f"[-] Server WHOIS tidak dikenal: {server}"
    except OSError as exc:
        return f"[-] Gagal melakukan query WHOIS ke {server}: {exc}."